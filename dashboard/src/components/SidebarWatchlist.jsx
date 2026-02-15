import React, { useState, useEffect, useRef } from "react";
import { ChevronLeft, ChevronRight, ArrowUpRight, ArrowDownRight, Wifi, WifiOff } from "lucide-react";
import { Tooltip } from "@mui/material";
import { useNavigate } from "react-router-dom";
import { DoughnutChart } from "./DoughnoutChart";
import '../styles/WatchList.css';
import { useSidebar } from '../context/SidebarContext';
import { useGeneralContext } from './GeneralContext';
import { stockService } from '../services/stockService';
import { io } from 'socket.io-client';
import { shouldShowLiveStatus } from '../lib/utils';
import { WS_URL } from '../config/api';

const initialIndices = [
  { symbol: "NIFTY 50", name: "NIFTY 50", value: 11504.95, change: -0.10, percent: -0.10 },
  { symbol: "SENSEX", name: "SENSEX", value: 38845.82, change: -0.34, percent: -0.34 },
];

const SidebarWatchlist = () => {
  const { collapsed, toggleSidebar } = useSidebar();
  const { setSelectedStock } = useGeneralContext();
  const [currentPage, setCurrentPage] = useState(0);
  const stocksPerPage = 8;
  const navigate = useNavigate();
  const [stocks, setStocks] = useState([]);
  const [indices, setIndices] = useState(initialIndices);
  const [previousStocks, setPreviousStocks] = useState([]);
  const [priceChanges, setPriceChanges] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdateTime, setLastUpdateTime] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  const priceChangeTimeouts = useRef({});
  const [companyInfoMap, setCompanyInfoMap] = useState({});
  const socketRef = useRef(null);

  // Fetch all company info on mount
  useEffect(() => {
    const fetchCompanyInfo = async () => {
      try {
        const companyData = await stockService.getCompanyInfo();
        
        const map = {};
        companyData.forEach(info => { 
          map[info.symbol] = info; 
        });
        setCompanyInfoMap(map);
      } catch (error) {
        console.error('SidebarWatchlist: Error fetching company info:', error);
      }
    };
    
    fetchCompanyInfo();
  }, []);

  // Load stock list from REST immediately so sidebar never stays on "Loading stocks..." (live updates come via WebSocket)
  useEffect(() => {
    let isMounted = true;
    const loadStocksFromRest = async () => {
      try {
        const allStocks = await stockService.getAllStocks();
        if (!isMounted) return;
        if (Array.isArray(allStocks) && allStocks.length > 0) {
          const processedStocks = allStocks.map(stock => ({
            symbol: stock.symbol || 'UNKNOWN',
            price: stock.price ?? 0,
            percent: stock.percent ?? 0,
            volume: stock.volume ?? '-',
            previousClose: stock.previousClose ?? (stock.price ? stock.price * (1 + (stock.percent || 0) / 100) : 0),
            name: stock.name || stock.fullName || stock.symbol || 'Unknown Stock',
          }));
          setStocks(processedStocks);
          setLoading(false);
        }
      } catch (err) {
        if (isMounted) setLoading(false);
      }
    };
    loadStocksFromRest();
    return () => { isMounted = false; };
  }, []);

  // WebSocket connection setup
  useEffect(() => {
    console.log('Setting up WebSocket connection...');
    console.log('WebSocket URL:', WS_URL);
    
    // Initialize socket connection with better reconnection settings
    socketRef.current = io(WS_URL, {
      transports: ['websocket', 'polling'],
      timeout: 20000,
      forceNew: true,
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      randomizationFactor: 0.5
    });

    const socket = socketRef.current;

    // Connection events
    socket.on('connect', () => {
      console.log('WebSocket connected');
      setIsConnected(true);
      setConnectionStatus('connected');
      setError(null);
    });

    socket.on('disconnect', (reason) => {
      console.log('WebSocket disconnected:', reason);
      setIsConnected(false);
      setConnectionStatus('disconnected');
      if (reason === 'io server disconnect') {
        // Server disconnected, try to reconnect
        socket.connect();
      }
    });

    socket.on('connect_error', (error) => {
      console.error('WebSocket connection error:', error);
      setConnectionStatus('error');
      // Don't set error immediately - let fallback handle it
      // This prevents showing error before fallback data loads
    });

    // Stock data events
    socket.on('initialStockData', (data) => {
      console.log('Received initial stock data:', data.length, 'stocks');
      if (data && data.length > 0) {
        const processedData = data.map(stock => ({
          symbol: stock.symbol,
          price: stock.price,
          percent: stock.percentChange,
          volume: stock.volume ? stock.volume.toLocaleString() : '-',
          previousClose: stock.previousClose,
          name: stock.name,
          lastUpdate: stock.lastUpdate
        }));
        setStocks(processedData);
        setLastUpdateTime(new Date());
        setLoading(false);
      }
    });

    socket.on('stockUpdate', (stock) => {
      console.log('Received stock update for:', stock.symbol);
      
      // Check if this is an index update
      if (stock.symbol === 'NIFTY 50' || stock.symbol === 'SENSEX') {
        setIndices(prevIndices => {
          return prevIndices.map(idx => {
            if (idx.symbol === stock.symbol) {
              // Calculate change and percent change
              const change = stock.price - stock.previousClose;
              const percent = ((change / stock.previousClose) * 100);
              
              return {
                ...idx,
                value: stock.price,
                change: change,
                percent: percent
              };
            }
            return idx;
          });
        });
      } else {
        // Regular stock update
        setStocks(prevStocks => {
          const updatedStocks = prevStocks.map(prevStock => {
            if (prevStock.symbol === stock.symbol) {
              // Show price change animation
              const prevPrice = prevStock.price;
              const newPrice = stock.price;
              if (prevPrice !== newPrice) {
                setPriceChanges(prev => ({
                  ...prev,
                  [stock.symbol]: newPrice > prevPrice ? 'up' : 'down'
                }));
                
                // Clear animation after 2 seconds
                setTimeout(() => {
                  setPriceChanges(prev => {
                    const newChanges = { ...prev };
                    delete newChanges[stock.symbol];
                    return newChanges;
                  });
                }, 2000);
              }
              
              return {
                ...prevStock,
                price: stock.price,
                percent: stock.percentChange,
                volume: stock.volume ? stock.volume.toLocaleString() : '-',
                previousClose: stock.previousClose,
                name: stock.name,
                lastUpdate: stock.lastUpdate
              };
            }
            return prevStock;
          });
          return updatedStocks;
        });
      }
      
      setLastUpdateTime(new Date());
    });

    socket.on('bulkStockUpdate', (data) => {
      console.log('Received bulk stock update:', data.length, 'stocks');
      if (data && data.length > 0) {
        const processedData = data.map(stock => ({
          symbol: stock.symbol,
          price: stock.price,
          percent: stock.percentChange,
          volume: stock.volume ? stock.volume.toLocaleString() : '-',
          previousClose: stock.previousClose,
          name: stock.name,
          lastUpdate: stock.lastUpdate
        }));
        setStocks(processedData);
        setLastUpdateTime(new Date());
        setLoading(false);
      }
    });

    // Cleanup on unmount
    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
    };
  }, []);

  // Fallback data loading when WebSocket is not available
  useEffect(() => {
    let isMounted = true;
    let fallbackTimeout;
    let immediateFallbackTimeout;
    
    // Only load fallback data if WebSocket fails to connect
    const loadFallbackData = async () => {
      try {
        if (!isMounted) return;
        
        console.log('Loading fallback stock data...');
        const allStocks = await stockService.getAllStocks();
        
        if (!isMounted) return;
        
        // Validate the data before setting it
        if (Array.isArray(allStocks) && allStocks.length > 0) {
          const processedStocks = allStocks.map(stock => ({
            symbol: stock.symbol || 'UNKNOWN',
            price: stock.price || 0,
            percent: stock.percent || 0,
            volume: stock.volume || '-',
            previousClose: stock.previousClose || (stock.price ? stock.price * (1 + (stock.percent || 0) / 100) : 0),
            name: stock.name || stock.fullName || stock.symbol || 'Unknown Stock',
          }));
          
          setStocks(processedStocks);
          setLoading(false);
          setError(null);
          console.log('Fallback data loaded:', processedStocks.length, 'stocks');
        } else {
          console.warn('Fallback data is empty or invalid');
          // Don't set empty array - keep trying or use previous data
          if (stocks.length === 0) {
            setLoading(false);
          }
        }
        
      } catch (error) {
        if (isMounted) {
          console.error('Error loading fallback data:', error);
          // Only set error if we don't have any stocks loaded
          if (stocks.length === 0) {
            setError('Failed to load stock data. Please refresh the page.');
            setLoading(false);
          } else {
            // If we have some stocks, just log the error but don't show it
            console.warn('Fallback data failed but we have existing stocks, continuing...');
          }
        }
      }
    };
    
    // Try to load fallback data immediately in case WebSocket fails quickly
    immediateFallbackTimeout = setTimeout(() => {
      if (!isConnected && stocks.length === 0 && loading) {
        console.log('WebSocket not connected after 2 seconds, starting fallback load...');
        loadFallbackData();
      }
    }, 2000); // 2 second initial timeout
    
    // Set longer timeout to load fallback data if WebSocket doesn't connect
    fallbackTimeout = setTimeout(() => {
      if (!isConnected && stocks.length === 0) {
        console.log('WebSocket connection timeout (5s), loading fallback data');
        loadFallbackData();
      }
    }, 5000); // 5 second timeout
    
    // Cleanup
    return () => {
      isMounted = false;
      if (fallbackTimeout) {
        clearTimeout(fallbackTimeout);
      }
      if (immediateFallbackTimeout) {
        clearTimeout(immediateFallbackTimeout);
      }
    };
  }, [isConnected, stocks.length, loading]);

  // Show all stocks, not just those with company info
  const filteredStocks = stocks;
  
  const totalPages = Math.ceil(filteredStocks.length / stocksPerPage);
  const currentStocks = filteredStocks.slice(currentPage * stocksPerPage, (currentPage + 1) * stocksPerPage);
  
  const nextPage = () => setCurrentPage(p => Math.min(p + 1, totalPages - 1));
  const prevPage = () => setCurrentPage(p => Math.max(p - 1, 0));

  const handleStockClick = (stock) => {
    try {
      setSelectedStock(stock);
      navigate(`/stock/${encodeURIComponent(stock.symbol)}`, { replace: true });
      
      // Close sidebar on mobile screens when stock is clicked
      if (window.innerWidth < 768 && !collapsed) {
        toggleSidebar();
      }
    } catch (error) {
      console.error('Error navigating to stock:', error);
    }
  };

  if (error) {
    return (
      <aside className={`h-full bg-white shadow-lg rounded-xl flex flex-col overflow-y-auto transition-all duration-300 ease-in-out ${collapsed ? 'sidebar-collapsed w-20' : 'w-80'}`}>
        <div className="flex items-center justify-between p-3 border-b border-gray-100 bg-gradient-to-r from-blue-50 to-indigo-50 sidebar-toggle">
          {!collapsed && (
            <div className="flex items-center gap-2 animate-fade-in">
              <div className="w-2 h-2 bg-yellow-500 rounded-full animate-pulse"></div>
              <span className="font-bold text-lg text-gray-900 tracking-tight">NIFTY 50</span>
            </div>
          )}
          <button 
            onClick={toggleSidebar} 
            className="p-2 rounded-lg hover:bg-gray-100 transition-colors"
          >
            <svg className="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 19l-7-7 7-7" />
            </svg>
          </button>
        </div>
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center px-4">
            <div className="text-yellow-500 mb-2">⚠️</div>
            <p className="text-sm text-gray-600 mb-2">Data not available</p>
            <p className="text-xs text-gray-500">{error}</p>
            <button 
              onClick={() => window.location.reload()} 
              className="mt-3 px-3 py-1 text-xs bg-blue-100 text-blue-700 rounded hover:bg-blue-200 transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </aside>
    );
  }
  
  if (stocks.length === 0 && !loading) {
    return (
      <aside className={`h-full bg-white shadow-lg rounded-xl flex flex-col overflow-y-auto transition-all duration-300 ease-in-out ${collapsed ? 'sidebar-collapsed w-20' : 'w-80'}`}>
        <div className="flex items-center justify-between p-3 border-b border-gray-100 bg-gradient-to-r from-blue-50 to-indigo-50 sidebar-toggle">
          {!collapsed && (
            <div className="flex items-center gap-2 animate-fade-in">
              <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></div>
              <span className="font-bold text-lg text-gray-900 tracking-tight">NIFTY 50</span>
            </div>
          )}
          <button 
            onClick={toggleSidebar} 
            className="p-2 rounded-lg hover:bg-gray-100 transition-colors"
          >
            <svg className="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 19l-7-7 7-7" />
            </svg>
          </button>
        </div>
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="text-red-500 mb-2">⚠️</div>
            <p className="text-sm text-gray-600">No stocks loaded</p>
            <p className="text-xs text-gray-500 mt-1">Check console for debug info</p>
          </div>
        </div>
      </aside>
    );
  }
  
  if (loading) {
    return (
      <aside className={`h-full bg-white shadow-lg rounded-xl flex flex-col overflow-y-auto transition-all duration-300 ease-in-out ${collapsed ? 'sidebar-collapsed w-20' : 'w-80'}`}>
        <div className="flex items-center justify-between p-3 border-b border-gray-100 bg-gradient-to-r from-blue-50 to-indigo-50 sidebar-toggle">
          {!collapsed && (
            <div className="flex items-center gap-2 animate-fade-in">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              <span className="font-bold text-lg text-gray-900 tracking-tight">NIFTY 50</span>
            </div>
          )}
          <button 
            onClick={toggleSidebar} 
            className="p-2 rounded-lg hover:bg-gray-100 transition-colors"
          >
            <svg className="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 19l-7-7 7-7" />
            </svg>
          </button>
        </div>
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-2"></div>
            <p className="text-sm text-gray-600">Loading stocks...</p>
          </div>
        </div>
      </aside>
    );
  }
  
  const data = {
    labels: currentStocks.map(stock => stock.symbol),
    datasets: [{
        data: currentStocks.map(stock => stock.price),
        backgroundColor: ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#06B6D4', '#84CC16', '#F97316', '#EC4899', '#6366F1'],
        borderWidth: 0,
    }],
  };
  
  return (
    <aside className={`h-full bg-white shadow-lg rounded-xl flex flex-col overflow-y-auto transition-all duration-300 ease-in-out ${collapsed ? 'sidebar-collapsed w-20' : 'w-full md:w-80'} max-w-full`}>
      <div className="flex items-center justify-between p-2 sm:p-3 border-b border-gray-100 bg-gradient-to-r from-blue-50 to-indigo-50 sidebar-toggle">
        {!collapsed && (
          <div className="flex items-center gap-1.5 sm:gap-2 animate-fade-in min-w-0 flex-1">
            <div className={`w-2 h-2 rounded-full animate-pulse flex-shrink-0 ${
              isConnected ? 'bg-green-500' : 
              connectionStatus === 'connecting' ? 'bg-yellow-500' : 
              'bg-red-500'
            }`}></div>
            <span className="font-bold text-sm sm:text-lg text-gray-900 tracking-tight truncate">NIFTY 50</span>
            {isConnected && lastUpdateTime && shouldShowLiveStatus() && (
              <span className="text-xs text-gray-500 ml-1 sm:ml-2 whitespace-nowrap hidden sm:inline">
                Live • {lastUpdateTime.toLocaleTimeString()}
              </span>
            )}
            {!isConnected && connectionStatus === 'connecting' && (
              <span className="text-xs text-gray-500 ml-1 sm:ml-2 whitespace-nowrap hidden sm:inline">
                Connecting...
              </span>
            )}
          </div>
        )}
        <div className="flex items-center gap-2">
          {!collapsed && (
            <div className="flex items-center gap-1">
              {isConnected ? (
                <Wifi size={16} className="text-green-500" title="Real-time connection active" />
              ) : (
                <WifiOff size={16} className="text-red-500" title="Connection lost" />
              )}
          </div>
        )}
        <button 
          onClick={toggleSidebar} 
          className={`p-2 rounded-lg hover:bg-gray-200 transition-colors ${collapsed ? 'mx-auto' : ''}`}
          title={collapsed ? "Expand Watchlist" : "Collapse Watchlist"}
        >
          {collapsed ? <ChevronRight size={20} /> : <ChevronLeft size={20} />}
        </button>
        </div>
      </div>
      {!collapsed && (
        <div className="px-4 pt-2 pb-3 border-b border-gray-100 bg-white">
          <div className="flex items-start gap-2 text-xs text-gray-500 leading-relaxed">
            <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mt-0.5">
              <circle cx="12" cy="12" r="10"></circle>
              <polyline points="12 6 12 12 16 14"></polyline>
            </svg>
            <span>
              {(() => {
                // Check if we should show live status (9:00 AM to 3:30 PM, Mon-Fri)
                if (shouldShowLiveStatus()) {
                  const now = new Date();
                  return `Live • ${now.toLocaleTimeString()}`;
                } else {
                  // Show 24/7 trading message
                  return "Buy & Sell available 24/7. Real-time prices shown during market hours (Mon-Fri 9:00 AM - 3:30 PM)";
                }
              })()}
            </span>
          </div>
        </div>
      )}

      {/* Collapsed state - show stock symbols */}
      {collapsed && (
        <div className="flex-1 flex flex-col py-2">
          {/* Stock count indicator */}
          <div className="flex items-center justify-center py-2 mb-3">
            <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
              <span className="text-sm font-bold text-blue-700">{filteredStocks.length}</span>
            </div>
          </div>
          
          {currentStocks.slice(0, 8).map((stock, index) => (
            <div
              key={stock.symbol}
              className="flex items-center justify-center py-3 px-2 cursor-pointer hover:bg-gray-100 transition-colors group"
              onClick={() => handleStockClick(stock)}
              title={`${stock.symbol} - ₹${stock.price.toLocaleString()}`}
            >
              <div className="w-12 h-12 bg-gray-100 rounded-lg flex items-center justify-center group-hover:bg-blue-100 transition-colors border border-gray-200 group-hover:border-blue-300">
                <span className="font-bold text-lg text-gray-700 group-hover:text-blue-700">
                  {stock.symbol.charAt(0)}
                </span>
              </div>
            </div>
          ))}
          {currentStocks.length === 0 && (
            <div className="flex items-center justify-center py-3 px-2">
              <div className="w-12 h-12 bg-gray-100 rounded-lg flex items-center justify-center border border-gray-200">
                <span className="font-bold text-lg text-gray-500">-</span>
              </div>
            </div>
          )}
        </div>
      )}

      {!collapsed && (
        <div className="flex-1 flex flex-col animate-fade-in sidebar-content">
          <div className="flex items-center gap-4 px-4 py-3 border-b border-gray-50 bg-gray-50">
            {indices.map((idx) => (
              <div key={idx.symbol} className="flex flex-col items-start text-xs">
                <span className="font-semibold text-gray-700 tracking-tight">{idx.name}</span>
                <span className={`flex items-center gap-1 font-bold ${idx.change >= 0 ? "text-green-600" : "text-red-500"}`}>
                  {idx.value.toLocaleString()}
                  <span className="ml-1 flex items-center">{idx.change >= 0 ? <ArrowUpRight size={12}/> : <ArrowDownRight size={12}/>} {Math.abs(idx.percent).toFixed(2)}%</span>
                </span>
              </div>
            ))}
          </div>

          <div className="flex-1 flex flex-col">
            <div className="flex items-center justify-between px-4 py-2 border-b border-gray-100 bg-gray-50">
              <span className="text-sm font-medium text-gray-600">
                {totalPages > 0 ? `${currentPage + 1} of ${totalPages}` : '0 of 0'}
              </span>
              <div className="flex items-center gap-2">
                <button onClick={prevPage} className="p-1.5 rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50" disabled={currentPage === 0}>
                    <ChevronLeft size={16} />
                </button>
                <button onClick={nextPage} className="p-1.5 rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50" disabled={totalPages === 0 || currentPage >= totalPages - 1}>
                    <ChevronRight size={16} />
                </button>
              </div>
            </div>

            {loading ? (
              <div className="p-4 space-y-3">
                  {[...Array(8)].map((_, i) => (
                      <div key={i} className="h-12 bg-gray-200 rounded animate-pulse"></div>
                  ))}
              </div>
            ) : (
                <ul className="divide-y divide-gray-50">
                    {currentStocks.map((stock) => {
                        const fullName = companyInfoMap[stock.symbol]?.company_name || stock.name;
                        const isDown = stock.percent < 0;
                        const formattedPercent = typeof stock.percent === 'number' ? Math.abs(stock.percent).toFixed(2) : 'N/A';
                        // Use previousClose for accurate absolute change
                        const absChange = (typeof stock.price === 'number' && typeof stock.previousClose === 'number')
                          ? stock.price - stock.previousClose
                          : 0;
                        const tooltipText = `${isDown ? 'Loss' : 'Profit'}: ${absChange < 0 ? '' : '+'}${absChange.toFixed(2)} (${formattedPercent}%)`;
                        return (
                            <li
                                key={stock.symbol}
                                className={`stock-item grid grid-cols-[1fr,auto] items-center gap-2 sm:gap-3 px-3 sm:px-4 py-2.5 sm:py-3 group hover:bg-gray-50 transition-all cursor-pointer border-l-2 border-transparent hover:border-blue-200 ${priceChanges[stock.symbol] === 'up' ? 'price-up' : priceChanges[stock.symbol] === 'down' ? 'price-down' : ''}`}
                                onClick={() => handleStockClick(stock)}
                            >
                                <div className="min-w-0">
                                    <Tooltip title={fullName} arrow>
                                        <span className="font-bold text-xs sm:text-sm text-gray-900 tabular-nums block truncate">{stock.symbol}</span>
                                    </Tooltip>
                                    <Tooltip title={`Volume: ${stock.volume} `} arrow>
                                        <span className="text-xs text-gray-500 block cursor-pointer truncate">{stock.volume} </span>
                                    </Tooltip>
                                </div>
                                <div className="flex flex-col items-end min-w-[80px] sm:min-w-[96px] text-right">
                                    <Tooltip title={`Price: ₹${stock.price.toLocaleString()}`} arrow>
                                        <span className={`font-bold text-base sm:text-lg text-black tabular-nums leading-tight ${priceChanges[stock.symbol] === 'up' ? 'price-up' : priceChanges[stock.symbol] === 'down' ? 'price-down' : ''}`}>
                                            ₹{typeof stock.price === 'number' ? stock.price.toLocaleString() : 'N/A'}
                                        </span>
                                    </Tooltip>
                                    <Tooltip title={tooltipText} arrow>
                                        <span className={`inline-flex items-center justify-end gap-0.5 sm:gap-1 text-xs sm:text-sm font-semibold ${isDown ? 'text-red-500' : 'text-green-600'}`} style={{ marginTop: 2 }}>
                                            {isDown ? <ArrowDownRight size={12} className="sm:w-3.5 sm:h-3.5"/> : <ArrowUpRight size={12} className="sm:w-3.5 sm:h-3.5"/>}
                                            <span className="whitespace-nowrap">{absChange < 0 ? '' : '+'}{typeof absChange === 'number' ? absChange.toFixed(2) : 'N/A'} ({formattedPercent}%)</span>
                                        </span>
                                    </Tooltip>
                                </div>
                            </li>
                        );
                    })}
                </ul>
            )}

            <div className="flex flex-col items-center justify-center py-6 px-4 bg-gradient-to-br from-gray-50 to-white border-t border-gray-100">
                <div className="font-semibold text-base text-gray-700 mb-4">Market Allocation</div>
                <div className="relative" style={{ width: '100%', maxWidth: 300, height: 300 }}>
                    <DoughnutChart data={data} />
                </div>
            </div>
          </div>
        </div>
      )}
    </aside>
  );
};

export default SidebarWatchlist;