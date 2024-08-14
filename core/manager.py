import glob
import importlib
import os
import sys

from core.logging import logger


def get_rules(role):
    return [os.path.splitext(os.path.basename(r))[0] for r in glob.glob('rules/**/rule_*.py', recursive=True)] if role == 'attacker' else []


def rule_manager(role):
    all_rules = get_rules(role)
    loaded_rules = {}

    for r in glob.glob('rules/**/'):
        if r not in sys.path:
            sys.path.insert(0, r)

    for rule_name in all_rules:
        try:
            mod = importlib.import_module(rule_name)
            loaded_rules[rule_name] = mod.Rule()
            logger.info(f"Imported rule {rule_name}")
        except ImportError as e:
            logger.error(f"Failed to import rule {rule_name}: {e}")

    return loaded_rules
