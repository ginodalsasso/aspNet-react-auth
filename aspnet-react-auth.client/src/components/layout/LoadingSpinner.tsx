import React from "react";

const LoadingSpinner: React.FC = () => {

    return (
        <div aria-label="Loading in progress">        
            <div className="loader" />
            <p>Loading, Please wait...</p>
        </div>
    )
};

export default LoadingSpinner;
