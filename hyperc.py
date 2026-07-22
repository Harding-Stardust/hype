r''' This file should be places in the folder pointed out by typing
print(idaapi.get_user_idadir()) in IDA
My machine: %APPDATA%\Hex-Rays\IDA Pro\hyperc.py
In the same directory, put shortcuts.cfg there also
'''
import idaapi
import community_base as cb

cb.log_print(f"Start of {__file__}", arg_type="INFO")

cb.log_print(f"Working on file {cb.input_file.idb_path}")

cb.log_print(f"End of {__file__}", arg_type="INFO")