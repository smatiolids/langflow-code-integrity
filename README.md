# Langflow Code Integrity Checker

This script is used to check if the code in the Langflow flow JSON file was changed by the user.

Export the flow to a json file and inspect it with this script.

## Usage
```bash
python check_flow.py <flow_json_file>
```

## Example

Example of a flow JSON file with changes:
```bash
python check_flow.py Edited.json

--------------------------------------------------------------------------------
Components with Changes:
--------------------------------------------------------------------------------

Component ID: Agent-JWq8E - Agent
```

Example of a flow JSON file without changes:

```bash
python check_flow.py Not_edited.json
================================================================================
No components with changes found.
```


## Requirements
- Python 3.10+
- Langflow 1.6.0+
- Langflow 1.7.0+

## License