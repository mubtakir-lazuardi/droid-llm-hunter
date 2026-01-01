import subprocess
import shutil
import os
from .base import Decompiler
from core import log

class ApktoolHandler(Decompiler):
    def __init__(self, apktool_path: str = "apktool"):
        self.apktool_path = apktool_path
        if not self._is_apktool_installed():
            raise FileNotFoundError(
                "Apktool is not installed or not in the system's PATH. "
                "Please install Apktool and ensure it is accessible."
            )

    def _is_apktool_installed(self) -> bool:
        return shutil.which(self.apktool_path) is not None

    def decompile(self, apk_path: str, output_dir: str):
        log.info(f"Starting decompilation of {apk_path} with Apktool...")
        framework_dir = "output/framework"
        os.makedirs(framework_dir, exist_ok=True)
        command = [
            self.apktool_path,
            "d",
            "-f",
            apk_path,
            "-o",
            output_dir,
            "-p",
            framework_dir,
        ]
        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )
            log.success(f"Successfully decompiled {apk_path} to {output_dir}")
            log.debug(f"Apktool Output:\n{result.stdout}")
        except FileNotFoundError:
            log.error(f"Error: '{self.apktool_path}' not found. Is Apktool installed and in your PATH?")
            raise
        except subprocess.CalledProcessError as e:
            log.error(f"An error occurred while running Apktool on {apk_path}.")
            log.error(f"Return Code: {e.returncode}")
            log.error(f"Output:\n{e.stderr}")
            raise
