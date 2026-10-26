import yaml

def parse_config(raw_yaml):
    # Unsafe YAML loader
    return yaml.load(raw_yaml, Loader=yaml.Loader)
