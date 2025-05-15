import React from 'react';

const SearchHistory = ({ 
  history, 
  onSelect, 
  onClear, 
  type = 'IP',
  className = '' 
}) => {
  if (!history || history.length === 0) return null;

  return (
    <div className={`space-y-4 ${className}`}>
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Recent Searches</h3>
        <button
          onClick={onClear}
          className="text-sm text-gray-400 hover:text-white transition-colors"
        >
          Clear History
        </button>
      </div>
      <div className="space-y-2">
        {history.map((item, index) => (
          <button
            key={index}
            onClick={() => onSelect(item)}
            className="w-full p-3 bg-gray-800/50 hover:bg-gray-800 border border-gray-700 rounded-lg text-left transition-colors group"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-white font-medium">{item.query}</p>
                <p className="text-sm text-gray-400">
                  {new Date(item.timestamp).toLocaleString()}
                </p>
              </div>
              <div className="opacity-0 group-hover:opacity-100 transition-opacity">
                <svg
                  className="w-5 h-5 text-gray-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M9 5l7 7-7 7"
                  />
                </svg>
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
};

export default SearchHistory; 