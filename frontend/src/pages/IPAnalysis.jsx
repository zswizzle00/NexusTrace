import React, { useState, useEffect } from 'react';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';
import SearchHistory from '../components/SearchHistory';

const IPAnalysis = () => {
  const [ipAddress, setIpAddress] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [searchHistory, setSearchHistory] = useState([]);

  // Load search history from localStorage on component mount
  useEffect(() => {
    const savedHistory = localStorage.getItem('ipSearchHistory');
    if (savedHistory) {
      setSearchHistory(JSON.parse(savedHistory));
    }
  }, []);

  // Save search history to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem('ipSearchHistory', JSON.stringify(searchHistory));
  }, [searchHistory]);

  const addToHistory = (query) => {
    const newHistory = [
      { query, timestamp: new Date().toISOString() },
      ...searchHistory.filter(item => item.query !== query)
    ].slice(0, 10); // Keep only the 10 most recent searches
    setSearchHistory(newHistory);
  };

  const clearHistory = () => {
    setSearchHistory([]);
    localStorage.removeItem('ipSearchHistory');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      // TODO: Replace with actual API call
      const response = await fetch(`/api/ip/${ipAddress}`);
      const data = await response.json();
      setResults(data);
      addToHistory(ipAddress);
    } catch (err) {
      setError('Failed to fetch IP analysis results. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleHistorySelect = (item) => {
    setIpAddress(item.query);
    // Optionally, you can automatically trigger the search
    // handleSubmit(new Event('submit'));
  };

  return (
    <div className="space-y-8">
      {/* Search Section */}
      <div className="card">
        <h2 className="text-2xl font-bold text-white mb-6">IP Address Analysis</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="ipAddress" className="block text-sm font-medium text-gray-300 mb-2">
              Enter IP Address
            </label>
            <div className="flex gap-4">
              <input
                type="text"
                id="ipAddress"
                value={ipAddress}
                onChange={(e) => setIpAddress(e.target.value)}
                placeholder="e.g., 8.8.8.8"
                className="input-field"
                required
                pattern="^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
              />
              <button
                type="submit"
                disabled={isLoading}
                className="btn btn-primary min-w-[120px]"
              >
                {isLoading ? <LoadingSpinner /> : 'Analyze'}
              </button>
            </div>
          </div>
        </form>

        {/* Search History */}
        <div className="mt-6 pt-6 border-t border-gray-700">
          <SearchHistory
            history={searchHistory}
            onSelect={handleHistorySelect}
            onClear={clearHistory}
            type="IP"
          />
        </div>
      </div>

      {/* Error Message */}
      <ErrorMessage message={error} />

      {/* Results Section */}
      {results && (
        <div className="space-y-6">
          {/* Basic Information */}
          <div className="card">
            <h3 className="text-xl font-semibold text-white mb-4">Basic Information</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-gray-400 text-sm">IP Address</p>
                <p className="text-white font-medium">{results.ip}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Country</p>
                <p className="text-white font-medium">{results.country}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">City</p>
                <p className="text-white font-medium">{results.city}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">ISP</p>
                <p className="text-white font-medium">{results.isp}</p>
              </div>
            </div>
          </div>

          {/* Threat Intelligence */}
          <div className="card">
            <h3 className="text-xl font-semibold text-white mb-4">Threat Intelligence</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg">
                <div>
                  <p className="text-gray-400 text-sm">Reputation Score</p>
                  <p className="text-white font-medium">{results.reputation_score}/100</p>
                </div>
                <div className={`px-3 py-1 rounded-full text-sm font-medium ${
                  results.reputation_score > 70 ? 'bg-green-500/20 text-green-400' :
                  results.reputation_score > 30 ? 'bg-yellow-500/20 text-yellow-400' :
                  'bg-red-500/20 text-red-400'
                }`}>
                  {results.reputation_score > 70 ? 'Safe' :
                   results.reputation_score > 30 ? 'Suspicious' :
                   'Malicious'}
                </div>
              </div>
              
              {results.threats && results.threats.length > 0 && (
                <div className="space-y-2">
                  <p className="text-gray-400 text-sm">Known Threats</p>
                  <div className="space-y-2">
                    {results.threats.map((threat, index) => (
                      <div key={index} className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                        <p className="text-red-400 font-medium">{threat.type}</p>
                        <p className="text-gray-400 text-sm">{threat.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Network Information */}
          <div className="card">
            <h3 className="text-xl font-semibold text-white mb-4">Network Information</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-gray-400 text-sm">ASN</p>
                <p className="text-white font-medium">{results.asn}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Organization</p>
                <p className="text-white font-medium">{results.organization}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Network Range</p>
                <p className="text-white font-medium">{results.network_range}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Hostname</p>
                <p className="text-white font-medium">{results.hostname || 'N/A'}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default IPAnalysis; 