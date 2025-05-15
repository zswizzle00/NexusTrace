import React, { useState, useEffect } from 'react';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';
import SearchHistory from '../components/SearchHistory';

const DomainAnalysis = () => {
  const [domain, setDomain] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [searchHistory, setSearchHistory] = useState([]);

  // Load search history from localStorage on component mount
  useEffect(() => {
    const savedHistory = localStorage.getItem('domainSearchHistory');
    if (savedHistory) {
      setSearchHistory(JSON.parse(savedHistory));
    }
  }, []);

  // Save search history to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem('domainSearchHistory', JSON.stringify(searchHistory));
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
    localStorage.removeItem('domainSearchHistory');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      // TODO: Replace with actual API call
      const response = await fetch(`/api/domain/${domain}`);
      const data = await response.json();
      setResults(data);
      addToHistory(domain);
    } catch (err) {
      setError('Failed to fetch domain analysis results. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleHistorySelect = (item) => {
    setDomain(item.query);
  };

  return (
    <div className="space-y-8">
      {/* Search Section */}
      <div className="card">
        <h2 className="text-2xl font-bold text-white mb-6">Domain Analysis</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="domain" className="block text-sm font-medium text-gray-300 mb-2">
              Enter Domain
            </label>
            <div className="flex gap-4">
              <input
                type="text"
                id="domain"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="e.g., example.com"
                className="input-field"
                required
                pattern="^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
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
            type="Domain"
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
                <p className="text-gray-400 text-sm">Domain</p>
                <p className="text-white font-medium">{results.domain}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Registrar</p>
                <p className="text-white font-medium">{results.registrar}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Creation Date</p>
                <p className="text-white font-medium">{new Date(results.creation_date).toLocaleDateString()}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Expiration Date</p>
                <p className="text-white font-medium">{new Date(results.expiration_date).toLocaleDateString()}</p>
              </div>
            </div>
          </div>

          {/* DNS Records */}
          <div className="card">
            <h3 className="text-xl font-semibold text-white mb-4">DNS Records</h3>
            <div className="space-y-4">
              {results.dns_records && Object.entries(results.dns_records).map(([type, records]) => (
                <div key={type} className="space-y-2">
                  <p className="text-gray-400 text-sm">{type} Records</p>
                  <div className="space-y-2">
                    {records.map((record, index) => (
                      <div key={index} className="p-3 bg-gray-800/50 border border-gray-700 rounded-lg">
                        <p className="text-white font-medium">{record}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Security Information */}
          <div className="card">
            <h3 className="text-xl font-semibold text-white mb-4">Security Information</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg">
                <div>
                  <p className="text-gray-400 text-sm">SSL Status</p>
                  <p className="text-white font-medium">{results.ssl_status}</p>
                </div>
                <div className={`px-3 py-1 rounded-full text-sm font-medium ${
                  results.ssl_status === 'Valid' ? 'bg-green-500/20 text-green-400' :
                  results.ssl_status === 'Expired' ? 'bg-red-500/20 text-red-400' :
                  'bg-yellow-500/20 text-yellow-400'
                }`}>
                  {results.ssl_status}
                </div>
              </div>

              {results.security_issues && results.security_issues.length > 0 && (
                <div className="space-y-2">
                  <p className="text-gray-400 text-sm">Security Issues</p>
                  <div className="space-y-2">
                    {results.security_issues.map((issue, index) => (
                      <div key={index} className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                        <p className="text-red-400 font-medium">{issue.type}</p>
                        <p className="text-gray-400 text-sm">{issue.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DomainAnalysis; 