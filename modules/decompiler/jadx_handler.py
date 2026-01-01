import subprocess
import shutil
import os
from core import log

class JadxHandler:
    def __init__(self, jadx_path: str = None):
        if jadx_path:
             self.jadx_path = jadx_path
        else:
             self.jadx_path = shutil.which("jadx")
             
        if not self.jadx_path:
            log.warning("JADX not found in PATH or configuration. Please install JADX to use Java source code analysis.")

    def is_available(self) -> bool:
        return self.jadx_path is not None

    def decompile(self, apk_path: str, output_dir: str) -> bool:
        """
        Decompiles the APK using JADX to the specified output directory.
        """
        if not self.is_available():
            log.error("Cannot decompile with JADX: Tool not found.")
            return False

        apk_abspath = os.path.abspath(apk_path)
        output_abspath = os.path.abspath(output_dir)

        if not os.path.exists(apk_abspath):
            log.error(f"APK file not found: {apk_abspath}")
            return False

        # Create output directory if it doesn't exist
        os.makedirs(output_abspath, exist_ok=True)

        log.info(f"Decompiling {apk_abspath} with JADX...")
        
        try:
            # Removed --no-res and --no-assets as they are not standard JADX CLI flags or vary by version.
            # We let JADX handle resources (it puts them in 'resources' folder usually).
            cmd = [self.jadx_path, "-d", output_abspath, apk_abspath]
            
            # Log command for debugging
            log.debug(f"Executing command: {' '.join(cmd)}")
            
            # Run the command with check=False to handle partial failures manually
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                check=False 
            )
            
            # Check if output directory has content (specifically 'sources' which Jadx makes)
            sources_path = os.path.join(output_abspath, "sources")
            has_sources = os.path.exists(sources_path) and os.listdir(sources_path)
            
            if result.returncode == 0:
                log.success(f"JADX decompilation successful: {output_abspath}")
                return True
            elif has_sources:
                 log.warning(f"JADX finished with errors (exit code {result.returncode}), but source code was generated. Proceeding...")
                 log.debug(f"JADX STDOUT: {result.stdout}")
                 return True
            else:
                 log.error(f"JADX failed with exit code {result.returncode} and no sources found.")
                 log.error(f"STDOUT: {result.stdout}")
                 log.error(f"STDERR: {result.stderr}")
                 return False

        except Exception as e:
            log.error(f"An unexpected error occurred during JADX decompilation: {e}")
            return False
