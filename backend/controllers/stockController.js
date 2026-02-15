const Stock = require('../model/StockModel');
const YahooFinance = require('yahoo-finance2').default;
const yahooFinance = new YahooFinance();
yahooFinance._notices.suppress(['yahooSurvey']);
const CompanyInfo = require('../model/CompanyInfoModel');
const stockCache = require('../services/stockCache');

exports.getStocks = async (req, res, next) => {
  try {
    console.log('Fetching all stocks from database');
    const stocks = await Stock.find();
    console.log(`Found ${stocks.length} stocks`);
    res.json(stocks);
  } catch (err) {
    console.error('Error fetching stocks:', err);
    next(err);
  }
};

exports.getStockBySymbol = async (req, res, next) => {
  try {
    console.log('Fetching stock by symbol:', req.params.symbol);
    const stock = await Stock.findOne({ symbol: req.params.symbol.toUpperCase() });
    if (!stock) {
      console.log('Stock not found:', req.params.symbol);
      return res.status(404).json({ error: 'Stock not found' });
    }
    res.json(stock);
  } catch (err) {
    console.error('Error fetching stock by symbol:', err);
    next(err);
  }
};

const CHUNK_SIZE = 12;
const DELAY_BETWEEN_CHUNKS_MS = 3000;

function mapQuoteToGetStocksDataItem(data) {
  if (!data || data.regularMarketPrice == null) return { symbol: (data?.symbol || '').replace('.NS', ''), error: 'No data' };
  const previousClose = data.regularMarketPreviousClose || 0;
  const baseSymbol = (data.symbol || '').replace('.NS', '');
  return {
    symbol: baseSymbol,
    name: data.shortName,
    price: data.regularMarketPrice,
    percentChange: data.regularMarketChangePercent,
    previousClose: previousClose || null,
    lowerCircuit: previousClose ? Number((previousClose * 0.95).toFixed(2)) : null,
    upperCircuit: previousClose ? Number((previousClose * 1.05).toFixed(2)) : null,
    volume: data.regularMarketVolume,
    marketCap: data.marketCap || null,
  };
}

exports.getStocksData = async (req, res) => {
  try {
    const symbols = req.query.symbols;
    if (!symbols) {
      return res.status(400).json({ data: [], error: 'No symbols provided' });
    }
    const symbolList = symbols.split(',').map(s => s.trim()).filter(Boolean);
    if (symbolList.length === 0) {
      return res.json({ data: [] });
    }

    // Prefer cache to avoid hitting Yahoo on every page load
    const cached = stockCache.getCachedDataForSymbols(symbolList);
    if (cached && cached.hasAll) {
      const data = cached.results.map(s => ({
        symbol: s.symbol,
        name: s.name,
        price: s.price,
        percentChange: s.percentChange ?? null,
        previousClose: s.previousClose ?? null,
        lowerCircuit: s.lowerCircuit ?? null,
        upperCircuit: s.upperCircuit ?? null,
        volume: s.volume ?? null,
        marketCap: s.marketCap ?? null,
      }));
      return res.json({ data });
    }
    let symbolsToFetch = symbolList;
    let mergedFromCache = [];
    if (cached && cached.results.length > 0) {
      const haveSet = new Set(cached.results.map(s => s.symbol.toUpperCase()));
      const missing = symbolList.filter(s => !haveSet.has(s.replace(/\.(NS|BSE)$/i, '').toUpperCase()));
      if (missing.length === 0) {
        return res.json({ data: cached.results.map(s => ({ symbol: s.symbol, name: s.name, price: s.price, percentChange: s.percentChange ?? null, previousClose: s.previousClose ?? null, lowerCircuit: s.lowerCircuit ?? null, upperCircuit: s.upperCircuit ?? null, volume: s.volume ?? null, marketCap: s.marketCap ?? null })) });
      }
      symbolsToFetch = missing;
      mergedFromCache = cached.results.map(s => ({ symbol: s.symbol, name: s.name, price: s.price, percentChange: s.percentChange ?? null, previousClose: s.previousClose ?? null, lowerCircuit: s.lowerCircuit ?? null, upperCircuit: s.upperCircuit ?? null, volume: s.volume ?? null, marketCap: s.marketCap ?? null }));
    }

    const yfSymbols = symbolsToFetch.map(s => /\.(NS|BSE)$/i.test(s) ? s : s + '.NS');
    const delayMs = (ms) => new Promise(resolve => setTimeout(resolve, ms));
    const maxRetries = 3;
    const baseDelay = 8000;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const results = [];
        for (let i = 0; i < yfSymbols.length; i += CHUNK_SIZE) {
          const chunk = yfSymbols.slice(i, i + CHUNK_SIZE);
          const quoteResults = await yahooFinance.quote(chunk, { return: 'array' });
          if (quoteResults && Array.isArray(quoteResults)) {
            results.push(...quoteResults.map(mapQuoteToGetStocksDataItem));
          }
          if (i + CHUNK_SIZE < yfSymbols.length) {
            await delayMs(DELAY_BETWEEN_CHUNKS_MS);
          }
        }
        const order = new Map(symbolList.map((s, i) => [s.replace(/\.(NS|BSE)$/i, '').toUpperCase(), i]));
        const combined = [...mergedFromCache, ...results].sort((a, b) => (order.get((a.symbol || '').toUpperCase()) ?? 999) - (order.get((b.symbol || '').toUpperCase()) ?? 999));
        return res.json({ data: combined });
      } catch (err) {
        const isRateLimit = err.message?.includes('429') || err.message?.includes('Too Many Requests') || err.message?.includes('crumb') || err.status === 429 || err.code === 429;
        if (isRateLimit && attempt < maxRetries) {
          const backoff = baseDelay * Math.pow(2, attempt - 1) + Math.random() * 2000;
          console.warn(`getStocksData rate limit, retrying in ${Math.round(backoff / 1000)}s`);
          await delayMs(backoff);
          continue;
        }
        throw err;
      }
    }
    res.status(503).json({ data: [], error: 'Service temporarily unavailable' });
  } catch (error) {
    console.error('Error in getStocksData:', error);
    res.status(500).json({ data: [], error: error.message });
  }
};

// Get static stock info (name, symbol, etc.) from MongoDB
exports.getStockInfo = async (req, res, next) => {
  try {
    const stock = await Stock.findOne({ symbol: req.params.symbol.toUpperCase() });
    if (!stock) return res.status(404).json({ error: 'Stock not found' });
    res.json({ symbol: stock.symbol, name: stock.fullName });
  } catch (err) {
    next(err);
  }
};

// Get live price and percent from Yahoo Finance
exports.getStockPrice = async (req, res, next) => {
  try {
    const data = await yahooFinance.quote(req.params.symbol);
    
    // Check if data is valid
    if (!data) {
      return res.status(404).json({ error: 'No data found' });
    }
    
    res.json({ price: data.regularMarketPrice, percent: data.regularMarketChangePercent });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch price' });
  }
};

// Get historical chart data from Yahoo Finance
exports.getStockHistory = async (req, res, next) => {
  const { range = '1d', interval = '5m' } = req.query;
  try {
    const result = await yahooFinance._chart(req.params.symbol, { range, interval });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch history' });
  }
};

// Remove company info logic from Yahoo Finance overview controller
// Only keep real-time price and trading logic in this file
// (No company info logic here)

// Alpha Vantage: Financials
exports.getCompanyFinancials = async (req, res) => {
  try {
    const data = await fetchCompanyFinancials(req.params.symbol);
    res.json(data);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
};

// Alpha Vantage: News
exports.getCompanyNews = async (req, res) => {
  try {
    const data = await fetchCompanyNews(req.params.symbol);
    res.json(data);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
};

// Alpha Vantage: History
exports.getCompanyHistory = async (req, res) => {
  try {
    const data = await fetchCompanyHistory(req.params.symbol);
    res.json(data);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
};

exports.getCompanyInfo = async (req, res) => {
  try {
    const symbol = req.params.symbol;
    
    if (!symbol) {
      return res.status(400).json({ 
        success: false,
        error: 'Stock symbol is required' 
      });
    }
    
    // Try exact match first, then uppercase, then case-insensitive
    let info = await CompanyInfo.findOne({ symbol: symbol });
    if (!info) {
      info = await CompanyInfo.findOne({ symbol: symbol.toUpperCase() });
    }
    if (!info) {
      info = await CompanyInfo.findOne({ symbol: { $regex: new RegExp(`^${symbol}$`, 'i') } });
    }
    
    if (info) {
      // Return consistent data structure with all fields
      res.json({
        success: true,
        data: info
      });
    } else {
      // Return consistent error structure
      res.status(404).json({ 
        success: false,
        error: 'No company info found for this stock symbol' 
      });
    }
  } catch (error) {
    console.error('Error fetching company info:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error while fetching company information' 
    });
  }
};

exports.getAllCompanyInfo = async (req, res) => {
  try {
    const all = await CompanyInfo.find({});
    res.json({
      success: true,
      data: all
    });
  } catch (error) {
    console.error('Error fetching all company info:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error while fetching company information' 
    });
  }
};