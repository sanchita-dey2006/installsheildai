"""Database operations compatibility shim."""
from analysis.operations import save_file, get_all_scans, get_all_scans_dict, get_scan_by_id, delete_all_scans, delete_scan_by_id

__all__ = ["save_file", "get_all_scans", "get_all_scans_dict", "get_scan_by_id", "delete_all_scans", "delete_scan_by_id"]
