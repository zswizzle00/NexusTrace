import React, { useState, useEffect } from 'react';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';
import SearchHistory from '../components/SearchHistory';
import DetailedReport from '../components/DetailedReport';

const URLAnalysis = () => {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [searchHistory, setSearchHistory] = useState([]);

  // Load search history from localStorage on component mount
  useEffect(() => {
    const savedHistory = localStorage.getItem('urlSearchHistory');
    if (savedHistory) {
      setSearchHistory(JSON.parse(savedHistory));
    }
  }, []);

  // Save search history to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem('urlSearchHistory', JSON.stringify(searchHistory));
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
    localStorage.removeItem('urlSearchHistory');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      // TODO: Replace with actual API call
      const response = await fetch(`/api/url/${encodeURIComponent(url)}`);
      const data = await response.json();
      setResults(data);
      addToHistory(url);
    } catch (err) {
      setError('Failed to fetch URL analysis results. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleHistorySelect = (item) => {
    setUrl(item.query);
  };

  const handleExport = (data) => {
    const report = {
      timestamp: new Date().toISOString(),
      url: data.url,
      analysis: data
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `url-analysis-${new Date().toISOString()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-8">
      {/* Search Section */}
      <div className="card">
        <h2 className="text-2xl font-bold text-white mb-6">URL Analysis</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="url" className="block text-sm font-medium text-gray-300 mb-2">
              Enter URL
            </label>
            <div className="flex gap-4">
              <input
                type="url"
                id="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="e.g., https://example.com"
                className="input-field"
                required
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
            type="URL"
          />
        </div>
      </div>

      {/* Error Message */}
      <ErrorMessage message={error} />

      {/* Results Section */}
      {results && (
        <div className="space-y-6">
          {/* Quick Overview */}
          <div className="card">
            <h3 className="text-xl font-semibold text-white mb-4">Quick Overview</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-gray-400 text-sm">URL</p>
                <p className="text-white font-medium break-all">{results.url}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Status</p>
                <p className="text-white font-medium">{results.status}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Content Type</p>
                <p className="text-white font-medium">{results.content_type}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Server</p>
                <p className="text-white font-medium">{results.server}</p>
              </div>
            </div>
          </div>

          {/* Detailed Report */}
          <div className="card">
            <DetailedReport
              data={results}
              type="URL"
              onExport={handleExport}
            />
          </div>
        </div>
      )}
    </div>
  );
};

export default URLAnalysis; 