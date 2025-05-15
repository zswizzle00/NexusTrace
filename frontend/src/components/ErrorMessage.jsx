import React from 'react';

const ErrorMessage = ({ message, className = '' }) => {
  if (!message) return null;

  return (
    <div className={`bg-red-500/10 border border-red-500 text-red-500 px-4 py-3 rounded-lg ${className}`}>
      {message}
    </div>
  );
};

export default ErrorMessage; 