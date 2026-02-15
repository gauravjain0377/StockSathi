// Stock service for fetching and managing stock data
import { getApiUrl, API_URL } from '../config/api';
import { isMarketOpen, getMarketDataStorageKey } from '../lib/utils';

// Log the API URL being used
console.log('StockService: API_URL =', API_URL);

// Fallback stock data from the seed file - All 50 stocks
const fallbackStocks = [
  { symbol: "RELIANCE", fullName: "Reliance Industries Ltd", price: 2745.30, percent: 0.42, volume: "3.2M", marketCap: "18.3T" },
  { symbol: "HDFCBANK", fullName: "HDFC Bank Ltd", price: 1578.40, percent: 0.75, volume: "2.9M", marketCap: "11.9T" },
  { symbol: "ICICIBANK", fullName: "ICICI Bank Ltd", price: 1076.20, percent: -0.60, volume: "4.3M", marketCap: "7.5T" },
  { symbol: "TCS", fullName: "Tata Consultancy Services Ltd", price: 3194.80, percent: -0.25, volume: "1.8M", marketCap: "11.7T" },
  { symbol: "BHARTIARTL", fullName: "Bharti Airtel Ltd", price: 1082.65, percent: 0.90, volume: "1.4M", marketCap: "6.1T" },
  { symbol: "INFY", fullName: "Infosys Ltd", price: 1567.90, percent: -1.15, volume: "2.1M", marketCap: "6.7T" },
  { symbol: "ITC", fullName: "ITC Ltd", price: 445.20, percent: 1.25, volume: "2.3M", marketCap: "5.6T" },
  { symbol: "KOTAKBANK", fullName: "Kotak Mahindra Bank Ltd", price: 1640.35, percent: 0.21, volume: "1.2M", marketCap: "4.8T" },
  { symbol: "LT", fullName: "Larsen & Toubro Ltd", price: 3410.00, percent: -2.34, volume: "850K", marketCap: "3.8T" },
  { symbol: "SBIN", fullName: "State Bank of India", price: 678.45, percent: -0.85, volume: "5.1M", marketCap: "6.1T" },
  { symbol: "AXISBANK", fullName: "Axis Bank Ltd", price: 1078.90, percent: -0.12, volume: "3.6M", marketCap: "4.2T" },
  { symbol: "HINDUNILVR", fullName: "Hindustan Unilever Ltd", price: 2565.00, percent: 1.45, volume: "1.1M", marketCap: "5.9T" },
  { symbol: "BAJFINANCE", fullName: "Bajaj Finance Ltd", price: 6789.45, percent: -0.95, volume: "420K", marketCap: "4.1T" },
  { symbol: "HCLTECH", fullName: "HCL Technologies Ltd", price: 1372.15, percent: -0.33, volume: "950K", marketCap: "3.9T" },
  { symbol: "MARUTI", fullName: "Maruti Suzuki India Ltd", price: 10895.60, percent: -1.20, volume: "450K", marketCap: "3.3T" },
  { symbol: "ASIANPAINT", fullName: "Asian Paints Ltd", price: 3245.80, percent: 0.65, volume: "850K", marketCap: "3.1T" },
  { symbol: "SUNPHARMA", fullName: "Sun Pharmaceutical Industries Ltd", price: 1245.30, percent: 0.45, volume: "1.2M", marketCap: "2.9T" },
  { symbol: "TITAN", fullName: "Titan Company Ltd", price: 3245.80, percent: 1.10, volume: "680K", marketCap: "2.9T" },
  { symbol: "ULTRACEMCO", fullName: "UltraTech Cement Ltd", price: 8456.70, percent: -0.75, volume: "320K", marketCap: "2.4T" },
  { symbol: "NTPC", fullName: "NTPC Ltd", price: 340.00, percent: 2.34, volume: "2.1M", marketCap: "2.2T" },
  { symbol: "TATAMOTORS", fullName: "Tata Motors Ltd", price: 678.90, percent: 2.15, volume: "3.8M", marketCap: "2.2T" },
  { symbol: "POWERGRID", fullName: "Power Grid Corporation of India Ltd", price: 320.00, percent: 1.23, volume: "1.8M", marketCap: "2.0T" },
  { symbol: "TATASTEEL", fullName: "Tata Steel Ltd", price: 150.00, percent: -2.34, volume: "4.2M", marketCap: "1.6T" },
  { symbol: "JSWSTEEL", fullName: "JSW Steel Ltd", price: 870.00, percent: 1.23, volume: "1.5M", marketCap: "1.5T" },
  { symbol: "NESTLEIND", fullName: "Nestle India Ltd", price: 2345.60, percent: 0.35, volume: "180K", marketCap: "2.3T" },
  { symbol: "HDFCLIFE", fullName: "HDFC Life Insurance Company Ltd", price: 680.00, percent: 2.34, volume: "950K", marketCap: "1.2T" },
  { symbol: "TECHM", fullName: "Tech Mahindra Ltd", price: 1250.00, percent: -2.34, volume: "1.2M", marketCap: "1.1T" },
  { symbol: "WIPRO", fullName: "Wipro Ltd", price: 527.80, percent: 0.28, volume: "1.1M", marketCap: "2.8T" },
  { symbol: "BAJAJFINSV", fullName: "Bajaj Finserv Ltd", price: 1750.00, percent: 3.45, volume: "680K", marketCap: "2.1T" },
  { symbol: "GRASIM", fullName: "Grasim Industries Ltd", price: 1900.00, percent: 1.23, volume: "450K", marketCap: "1.2T" },
  { symbol: "ADANIGREEN", fullName: "Adani Green Energy Ltd", price: 2100.00, percent: -5.67, volume: "320K", marketCap: "3.5T" },
  { symbol: "ADANIPORTS", fullName: "Adani Ports and SEZ Ltd", price: 980.00, percent: 3.45, volume: "850K", marketCap: "2.6T" },
  { symbol: "COALINDIA", fullName: "Coal India Ltd", price: 450.00, percent: 2.34, volume: "2.8M", marketCap: "1.5T" },
  { symbol: "BPCL", fullName: "Bharat Petroleum Corporation Ltd", price: 480.00, percent: 1.23, volume: "1.9M", marketCap: "1.1T" },
  { symbol: "UPL", fullName: "UPL Ltd", price: 650.00, percent: -2.34, volume: "1.2M", marketCap: "990B" },
  { symbol: "HINDALCO", fullName: "Hindalco Industries Ltd", price: 520.00, percent: 1.23, volume: "2.1M", marketCap: "1.6T" },
  { symbol: "EICHERMOT", fullName: "Eicher Motors Ltd", price: 4200.00, percent: 3.45, volume: "280K", marketCap: "1.1T" },
  { symbol: "DIVISLAB", fullName: "Divi's Laboratories Ltd", price: 3900.00, percent: 2.34, volume: "180K", marketCap: "990B" },
  { symbol: "CIPLA", fullName: "Cipla Ltd", price: 1250.00, percent: 2.34, volume: "1.1M", marketCap: "1.1T" },
  { symbol: "BRITANNIA", fullName: "Britannia Industries Ltd", price: 4200.00, percent: 3.45, volume: "320K", marketCap: "1.1T" },
  { symbol: "M&M", fullName: "Mahindra & Mahindra Ltd", price: 1800.00, percent: 3.45, volume: "850K", marketCap: "1.6T" },
  { symbol: "BAJAJ_AUTO", fullName: "Bajaj Auto Ltd", price: 7900.00, percent: 3.45, volume: "450K", marketCap: "1.5T" },
  { symbol: "HERO", fullName: "Hero MotoCorp Ltd", price: 3400.00, percent: 2.34, volume: "680K", marketCap: "1.1T" },
  { symbol: "DRREDDY", fullName: "Dr. Reddy's Laboratories Ltd", price: 5800.00, percent: 2.34, volume: "420K", marketCap: "990B" },
  { symbol: "DABUR", fullName: "Dabur India Ltd", price: 620.00, percent: 3.45, volume: "850K", marketCap: "1.1T" },
  { symbol: "APOLLOHOSP", fullName: "Apollo Hospitals Enterprise Ltd", price: 5800.00, percent: 2.34, volume: "180K", marketCap: "990B" },
  { symbol: "TATACONSUM", fullName: "Tata Consumer Products Ltd", price: 980.00, percent: 3.45, volume: "680K", marketCap: "1.1T" },
  { symbol: "ONGC", fullName: "Oil & Natural Gas Corporation Ltd", price: 270.00, percent: 2.34, volume: "3.2M", marketCap: "2.3T" },
  { symbol: "INDUSINDBK", fullName: "IndusInd Bank Ltd", price: 1450.00, percent: 2.34, volume: "950K", marketCap: "990B" },
  { symbol: "HDFC", fullName: "Housing Development Finance Corporation Ltd", price: 2850.00, percent: 1.85, volume: "1.2M", marketCap: "5.2T" }
];

// Helper function to get user-specific storage key
const getWatchlistKey = (userId) => `watchlists_${userId || 'default'}`;

// Enhanced fetch helper with better error handling
const fetchWithErrorHandling = async (url, options = {}) => {
  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });
    
    // Check if response is OK
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(`HTTP ${response.status}: ${errorData.message || response.statusText}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error(`Fetch error for ${url}:`, error);
    throw error;
  }
};

export const stockService = {
  async getAllStocks() {
    try {
      const url = getApiUrl('/api/stocks');
      console.log('StockService: Fetching stocks from:', url);
      
      const data = await fetchWithErrorHandling(url);
      // Backend may return raw array (res.json(stocks)) or object { success, stocks/data }
      const stocks = Array.isArray(data) ? data : (data?.stocks || data?.data || []);
      
      // If backend returns empty or insufficient data, use fallback
      if (stocks.length === 0 || stocks.length < 50) {
        console.warn('StockService: Insufficient stock data (' + stocks.length + ' stocks), using fallback');
        return fallbackStocks;
      }
      
      console.log('StockService: Successfully fetched', stocks.length, 'stocks');
      return stocks;
    } catch (error) {
      console.error('StockService: Error fetching stocks, using fallback:', error);
      console.error('StockService: Error details:', error.message);
      return fallbackStocks;
    }
  },

  async getStockData(symbol) {
    try {
      const data = await fetchWithErrorHandling(getApiUrl(`/api/stocks/${symbol}`));
      // Handle new response structure
      return data.success === true ? data.data : data;
    } catch (error) {
      console.error('StockService: Error fetching stock data:', error);
      return null;
    }
  },

  async getCompanyInfo() {
    try {
      const url = getApiUrl('/api/stocks/company-info');
      console.log('StockService: Fetching company info from:', url);
      
      const data = await fetchWithErrorHandling(url);
      // Handle new response structure
      if (data.success === false) {
        console.warn('StockService: Company info request failed:', data.error);
        return [];
      }
      const companies = data.companies || data.data || [];
      console.log('StockService: Successfully fetched', companies.length, 'company info entries');
      return companies;
    } catch (error) {
      console.error('StockService: Error fetching company info:', error);
      console.error('StockService: Error details:', error.message);
      // Return empty array - not critical for watchlist to work
      return [];
    }
  },

  async getMostTradedStocks() {
    try {
      const allStocks = await this.getAllStocks();
      return allStocks.slice(0, 8);
    } catch (error) {
      console.error('StockService: Error fetching most traded stocks:', error);
      return fallbackStocks.slice(0, 8);
    }
  },

  async getAllStocksWithData() {
    try {
      const allStocks = await this.getAllStocks();
      
      if (allStocks.length === 0) {
        return fallbackStocks;
      }
      
      return allStocks;
    } catch (error) {
      console.error('StockService: Error fetching all stocks with data:', error);
      return fallbackStocks;
    }
  },

  // Health check function
  async healthCheck() {
    try {
      const data = await fetchWithErrorHandling(getApiUrl('/api/health'));
      console.log('Health check response:', data);
      return data;
    } catch (error) {
      console.error('StockService: Health check failed:', error);
      return { status: 'error', message: error.message };
    }
  },

  // Fetch real-time market data for top gainers and losers
  async getMarketMovers() {
    try {
      // Check if we have cached data for today
      const storageKey = getMarketDataStorageKey();
      const cachedData = localStorage.getItem(storageKey);
      
      // If market is closed, return cached data if available
      if (!isMarketOpen()) {
        if (cachedData) {
          return JSON.parse(cachedData);
        }
      }
      
      // Fetch fresh data from API
      const allStocks = await this.getAllStocks();
      
      // Sort by percentage change to get top gainers and losers
      const sortedStocks = [...allStocks].sort((a, b) => 
        Math.abs(b.percent) - Math.abs(a.percent)
      );
      
      const topGainers = sortedStocks
        .filter(stock => stock.percent > 0)
        .slice(0, 5);
        
      const topLosers = sortedStocks
        .filter(stock => stock.percent < 0)
        .slice(0, 5);
      
      const marketData = {
        topGainers,
        topLosers,
        timestamp: new Date().toISOString()
      };
      
      // Cache the data if market is closed
      if (!isMarketOpen()) {
        localStorage.setItem(storageKey, JSON.stringify(marketData));
      }
      
      return marketData;
    } catch (error) {
      console.error('StockService: Error fetching market movers:', error);
      // Return cached data if available, otherwise fallback
      const storageKey = getMarketDataStorageKey();
      const cachedData = localStorage.getItem(storageKey);
      if (cachedData) {
        return JSON.parse(cachedData);
      }
      return {
        topGainers: fallbackStocks.filter(s => s.percent > 0).slice(0, 5),
        topLosers: fallbackStocks.filter(s => s.percent < 0).slice(0, 5),
        timestamp: new Date().toISOString()
      };
    }
  },

  // Watchlist management functions
  getUserWatchlists(userId) {
    try {
      const key = getWatchlistKey(userId);
      const stored = localStorage.getItem(key);
      return stored ? JSON.parse(stored) : [];
    } catch (error) {
      console.error('StockService: Error getting user watchlists:', error);
      return [];
    }
  },

  saveUserWatchlists(userId, watchlists) {
    try {
      const key = getWatchlistKey(userId);
      localStorage.setItem(key, JSON.stringify(watchlists));
    } catch (error) {
      console.error('StockService: Error saving user watchlists:', error);
    }
  },

  async getWatchlist(userId) {
    try {
      const watchlists = this.getUserWatchlists(userId);
      // Return the first watchlist's stocks or empty array
      return watchlists.length > 0 ? watchlists[0].stocks : [];
    } catch (error) {
      console.error('StockService: Error fetching watchlist:', error);
      return [];
    }
  },

  async getAllWatchlists(userId) {
    try {
      return this.getUserWatchlists(userId);
    } catch (error) {
      console.error('StockService: Error fetching all watchlists:', error);
      return [];
    }
  },

  async createWatchlist(userId, watchlistName) {
    try {
      const watchlists = this.getUserWatchlists(userId);
      const newWatchlist = {
        id: Date.now(),
        name: watchlistName,
        stocks: []
      };
      const updatedWatchlists = [...watchlists, newWatchlist];
      this.saveUserWatchlists(userId, updatedWatchlists);
      return newWatchlist;
    } catch (error) {
      console.error('StockService: Error creating watchlist:', error);
      return null;
    }
  },

  async updateWatchlist(userId, watchlistId, updatedWatchlist) {
    try {
      const watchlists = this.getUserWatchlists(userId);
      const updatedWatchlists = watchlists.map(w => 
        w.id === watchlistId ? { ...w, ...updatedWatchlist } : w
      );
      this.saveUserWatchlists(userId, updatedWatchlists);
      return true;
    } catch (error) {
      console.error('StockService: Error updating watchlist:', error);
      return false;
    }
  },

  async deleteWatchlist(userId, watchlistId) {
    try {
      const watchlists = this.getUserWatchlists(userId);
      const updatedWatchlists = watchlists.filter(w => w.id !== watchlistId);
      this.saveUserWatchlists(userId, updatedWatchlists);
      return true;
    } catch (error) {
      console.error('StockService: Error deleting watchlist:', error);
      return false;
    }
  },

  async addStockToWatchlist(userId, watchlistId, stock) {
    try {
      const watchlists = this.getUserWatchlists(userId);
      let stockAdded = false;
      
      const updatedWatchlists = watchlists.map(w => {
        if (w.id === watchlistId) {
          const stockExists = w.stocks.some(s => s.symbol === stock.symbol);
          if (!stockExists) {
            stockAdded = true;
            return { ...w, stocks: [...w.stocks, stock] };
          }
        }
        return w;
      });
      
      this.saveUserWatchlists(userId, updatedWatchlists);
      return stockAdded; // Return true only if stock was actually added
    } catch (error) {
      console.error('StockService: Error adding stock to watchlist:', error);
      return false;
    }
  },

  async removeStockFromWatchlist(userId, watchlistId, stockSymbol) {
    try {
      const watchlists = this.getUserWatchlists(userId);
      const updatedWatchlists = watchlists.map(w => {
        if (w.id === watchlistId) {
          return { ...w, stocks: w.stocks.filter(s => s.symbol !== stockSymbol) };
        }
        return w;
      });
      this.saveUserWatchlists(userId, updatedWatchlists);
      return true;
    } catch (error) {
      console.error('StockService: Error removing stock from watchlist:', error);
      return false;
    }
  },

  async getWatchlistSummary(userId) {
    try {
      const watchlists = this.getUserWatchlists(userId);
      const totalItems = watchlists.reduce((sum, w) => sum + w.stocks.length, 0);
      const allStocks = watchlists.flatMap(w => w.stocks);
      
      return {
        count: watchlists.length,
        items: allStocks.slice(0, 3), // Show first 3 items from all watchlists
        totalItems: totalItems,
        watchlists: watchlists
      };
    } catch (error) {
      console.error('StockService: Error fetching watchlist summary:', error);
      return {
        count: 0,
        items: [],
        totalItems: 0,
        watchlists: []
      };
    }
  }
};