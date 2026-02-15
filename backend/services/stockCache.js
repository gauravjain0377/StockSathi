/**
 * In-memory cache for live stock data. Shared between:
 * - index.js (WebSocket / background fetcher) - writes
 * - stockController.getStocksData - reads to avoid hitting Yahoo on every request
 */
const CACHE_MAX_AGE_MS = 2 * 60 * 1000; // 2 minutes - treat as fresh

let cache = new Map(); // symbol (e.g. 'RELIANCE') -> stock object
let lastUpdated = null;

function setCache(stocks) {
  cache.clear();
  if (Array.isArray(stocks)) {
    stocks.forEach(s => {
      if (s && s.symbol) cache.set(s.symbol, s);
    });
  }
  lastUpdated = Date.now();
}

function getCache() {
  return { cache: new Map(cache), lastUpdated };
}

function getCachedDataForSymbols(symbolList) {
  if (!symbolList || symbolList.length === 0) return null;
  if (lastUpdated == null || Date.now() - lastUpdated > CACHE_MAX_AGE_MS) return null;
  const normalized = symbolList.map(s => (typeof s === 'string' ? s.replace(/\.(NS|BSE)$/i, '') : s));
  const results = [];
  let hasAll = true;
  for (const sym of normalized) {
    const hit = cache.get(sym.toUpperCase()) || cache.get(sym);
    if (hit) results.push(hit);
    else hasAll = false;
  }
  return results.length > 0 ? { results, hasAll } : null;
}

module.exports = {
  setCache,
  getCache,
  getCachedDataForSymbols,
  CACHE_MAX_AGE_MS,
};
