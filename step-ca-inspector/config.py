import os
import sys
import yaml


class config:
    @classmethod
    def __init__(self):
        config_path = os.environ.get("STEP_CA_CERTAPI_CONFIGURATION")
        if config_path is None:
            print("No configuration file found")
            sys.exit(1)
        try:
            with open(config_path) as ymlfile:
                cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)
        except IOError:
            print("Cannot read configuration file")
            sys.exit(1)

        for k, v in cfg.items():
            setattr(self, k, v)

        for setting in ["database"]:
            if not hasattr(self, setting):
                print(f"Mandatory setting {setting} is not configured.")
                sys.exit(1)
