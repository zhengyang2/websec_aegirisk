"""Input validation utilities for risk engine configuration."""
import re
from typing import List, Optional
from fastapi import HTTPException, status


# API Key validation
def validate_api_key(api_key: str) -> None:
    """
    Validate API key format.
    
    Args:
        api_key: The API key to validate
        
    Raises:
        HTTPException: If validation fails
    """
    if not api_key or not isinstance(api_key, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key is required"
        )
    
    # Strip whitespace
    api_key = api_key.strip()
    
    # Check length (typical token_urlsafe(32) produces ~43 chars)
    if len(api_key) < 16 or len(api_key) > 128:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid API key format"
        )
    
    # Check for valid characters (alphanumeric, hyphen, underscore)
    if not re.match(r'^[A-Za-z0-9_-]+$', api_key):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid API key format"
        )


# Risk Engine Configuration validation
def validate_risk_score(value: int, field_name: str, min_val: int = 0, max_val: int = 100) -> None:
    """
    Validate risk score value.
    
    Args:
        value: The score value to validate
        field_name: Name of the field for error messages
        min_val: Minimum allowed value (default: 0)
        max_val: Maximum allowed value (default: 100)
        
    Raises:
        HTTPException: If validation fails
    """
    if not isinstance(value, int):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be an integer"
        )
    
    if value < min_val or value > max_val:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be between {min_val} and {max_val}"
        )


def validate_threshold(value: int, field_name: str) -> None:
    """
    Validate decision threshold value.
    
    Args:
        value: The threshold value to validate
        field_name: Name of the field for error messages
        
    Raises:
        HTTPException: If validation fails
    """
    validate_risk_score(value, field_name, min_val=0, max_val=100)


def validate_distance(value: float, field_name: str) -> None:
    """
    Validate distance value.
    
    Args:
        value: The distance value to validate (km)
        field_name: Name of the field for error messages
        
    Raises:
        HTTPException: If validation fails
    """
    if not isinstance(value, (int, float)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be a number"
        )
    
    # Reasonable range: 0 km to 40,000 km (Earth's circumference ~40,075 km)
    if value < 0 or value > 40000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be between 0 and 40000 km"
        )


def validate_speed(value: float, field_name: str) -> None:
    """
    Validate speed threshold value.
    
    Args:
        value: The speed value to validate (km/h)
        field_name: Name of the field for error messages
        
    Raises:
        HTTPException: If validation fails
    """
    if not isinstance(value, (int, float)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be a number"
        )
    
    # Reasonable range: 1 km/h to 10000 km/h (commercial planes ~900 km/h)
    if value < 1 or value > 10000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be between 1 and 10000 km/h"
        )


def validate_time_window(value: float, field_name: str) -> None:
    """
    Validate time window value.
    
    Args:
        value: The time window in hours
        field_name: Name of the field for error messages
        
    Raises:
        HTTPException: If validation fails
    """
    if not isinstance(value, (int, float)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be a number"
        )
    
    # Reasonable range: 0.1 hour (6 minutes) to 720 hours (30 days)
    if value < 0.1 or value > 720:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be between 0.1 and 720 hours"
        )


def validate_percentage(value: float, field_name: str) -> None:
    """
    Validate percentage value (0.0 to 1.0).
    
    Args:
        value: The percentage value to validate
        field_name: Name of the field for error messages
        
    Raises:
        HTTPException: If validation fails
    """
    if not isinstance(value, (int, float)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be a number"
        )
    
    if value < 0.0 or value > 1.0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be between 0.0 and 1.0"
        )


def validate_positive_integer(value: int, field_name: str, min_val: int = 1, max_val: int = 10000) -> None:
    """
    Validate positive integer value.
    
    Args:
        value: The integer value to validate
        field_name: Name of the field for error messages
        min_val: Minimum allowed value (default: 1)
        max_val: Maximum allowed value (default: 10000)
        
    Raises:
        HTTPException: If validation fails
    """
    if not isinstance(value, int):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be an integer"
        )
    
    if value < min_val or value > max_val:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be between {min_val} and {max_val}"
        )


def validate_hour(value: int, field_name: str) -> None:
    """
    Validate single hour value (0-23).
    
    Args:
        value: The hour value to validate
        field_name: Name of the field for error messages
        
    Raises:
        HTTPException: If validation fails
    """
    if not isinstance(value, int):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be an integer"
        )
    
    if value < 0 or value > 23:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be between 0 and 23"
        )


def validate_hour_list(hours: List[int], field_name: str) -> None:
    """
    Validate list of hours (0-23).
    
    Args:
        hours: List of hour values to validate
        field_name: Name of the field for error messages
        
    Raises:
        HTTPException: If validation fails
    """
    if not isinstance(hours, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be a list"
        )
    
    if len(hours) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} cannot be empty"
        )
    
    if len(hours) > 24:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} cannot have more than 24 hours"
        )
    
    for hour in hours:
        if not isinstance(hour, int):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_name} must contain only integers"
            )
        
        if hour < 0 or hour > 23:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_name} must contain values between 0 and 23"
            )
