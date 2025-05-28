from sqlalchemy.orm import Session
from typing import Dict, Any # Changed from Dict to Any for db_settings_cache initially
from ..models.db_server_setting import ServerSetting # Adjusted path assuming models.db_server_setting

# Define a dictionary to hold the loaded settings
db_settings_cache: Dict[str, Any] = {} # Explicitly type the cache

# Define default values in case they are not in the DB yet
from .settings import DEFAULT_SETTINGS

# Helper function to infer type from a string and parse another string accordingly
def _infer_and_parse_value(value_to_parse_str: str, type_reference_str: str):
    """
    Infers the data type from type_reference_str and parses value_to_parse_str
    into that type.
    Supported types: int, bool, str.
    """
    if type_reference_str.lower() in ["true", "false"]:
        return value_to_parse_str.lower() == "true"
    elif type_reference_str.isdigit():
        return int(value_to_parse_str)
    # Add other type inferences here if needed (e.g., float)
    return value_to_parse_str  # Default to string

# Helper function to get a string representation of the inferred type
def _get_type_description_string(default_value_str: str) -> str:
    """
    Returns a string description of the inferred type from default_value_str.
    """
    if default_value_str.lower() in ["true", "false"]:
        return "boolean"
    elif default_value_str.isdigit():
        return "integer"
    return "string"

def load_settings_from_db(db: Session):
    """
    Loads settings from the server_settings table into the cache.
    Uses default values if a setting is not found in the DB.
    Values are parsed into their inferred types (int, bool, str).
    """
    global db_settings_cache
    temp_cache: Dict[str, Any] = {}  # Use a temporary cache for loading

    settings_in_db = db.query(ServerSetting).all()
    # Ensure keys and values are strings when creating the map from DB objects
    db_settings_map: Dict[str, str] = {str(setting.name): str(setting.value) for setting in settings_in_db}

    for key, default_value_str in DEFAULT_SETTINGS.items():
        value_from_db_or_default_str = db_settings_map.get(key, default_value_str)
        
        try:
            parsed_value = _infer_and_parse_value(value_from_db_or_default_str, default_value_str)
            temp_cache[key] = parsed_value
        except ValueError as e:
            print(f"Warning: Could not parse setting '{key}' value '{value_from_db_or_default_str}' "
                  f"as type inferred from default '{default_value_str}'. Error: {e}. Using raw string from DB/default.")
            temp_cache[key] = value_from_db_or_default_str # Fallback to string
            
    db_settings_cache = temp_cache # Assign to global cache once loading is complete
    return db_settings_cache

def get_setting(name: str):
    """
    Retrieves a setting value from the cache.
    Raises RuntimeError if settings are not loaded.
    Raises KeyError if the setting name is not defined in DEFAULT_SETTINGS.
    """
    if not db_settings_cache:
        raise RuntimeError("Settings not loaded from DB. Application might not have initialized correctly.")
    
    try:
        return db_settings_cache[name]
    except KeyError as exc:
        # This implies 'name' was not in DEFAULT_SETTINGS when load_settings_from_db ran,
        # or load_settings_from_db had an issue for this key.
        raise KeyError(f"Setting '{name}' not found. Ensure it is defined in DEFAULT_SETTINGS and application is initialized.") from exc
            
def initialize_db_with_default_settings(db: Session):
    """
    Populates the server_settings table with default values if they don't exist.
    """
    for name, value_str in DEFAULT_SETTINGS.items():
        setting_exists = db.query(ServerSetting).filter(ServerSetting.name == name).first()
        if not setting_exists:
            type_desc = _get_type_description_string(value_str)
            description = f"Default value for {name}. Inferred type: {type_desc}."
            db_setting = ServerSetting(name=name, value=value_str, description=description) # Store default string value
            db.add(db_setting)
    db.commit()
