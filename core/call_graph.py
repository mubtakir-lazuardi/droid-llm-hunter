import re
import os
from collections import defaultdict
from core import log

class CallGraphBuilder:
    def __init__(self, decompiled_dir: str):
        self.decompiled_dir = decompiled_dir
        # Map: class_name -> list of (callee_class, callee_method)
        self.call_graph = defaultdict(set)
        # Map: class_name -> file_path
        self.class_to_file = {}
        # Regex patterns
        # Modifiers are matched generically as space-separated tokens (e.g.
        # "public final", "public abstract interface") — enumerating keywords
        # without allowing spaces between them silently dropped every class with
        # 2+ modifiers, which is the norm in Kotlin-compiled code.
        self.class_pattern = re.compile(r'^\.class\s+(?:[\w-]+\s+)*L([\w/$]+);')
        self.invoke_pattern = re.compile(r'invoke-\w+\s+\{.*\},\s+L([\w/$]+);->(\w+)\(')

    def build(self):
        log.info("Building call graph from Smali files...")
        count = 0
        for root, _, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith(".smali"):
                    file_path = os.path.join(root, file)
                    self._parse_file(file_path)
                    count += 1
        log.success(f"Call graph built from {count} files.")

    def _parse_file(self, file_path: str):
        current_class = None
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                
            for line in lines:
                line = line.strip()
                
                # Find class definition
                if line.startswith(".class"):
                    match = self.class_pattern.search(line)
                    if match:
                        current_class = match.group(1)
                        self.class_to_file[current_class] = file_path
                        continue
                
                # Find method invocations
                if line.startswith("invoke-") and current_class:
                    match = self.invoke_pattern.search(line)
                    if match:
                        callee_class = match.group(1)
                        callee_method = match.group(2)
                        
                        # Optimization: Ignore standard Android/Java calls to reduce noise
                        # Only track calls to classes within the app or libraries included in the apk
                        if not callee_class.startswith("java/") and not callee_class.startswith("android/"):
                            self.call_graph[current_class].add((callee_class, callee_method))
                            
        except Exception as e:
            log.warning(f"Error parsing smali file {file_path}: {e}")

    def path_to_class(self, file_path: str) -> str:
        """
        Derive the normalized class name (e.g. 'com/example/Foo') from a decompiled
        file path, working for BOTH Smali (apktool) and Java (JADX) outputs.

        Apktool: <output_dir>/smali[/_classesN]/com/example/Foo.smali
        JADX:    <output_dir>/sources/com/example/Foo.java

        Anchored to self.decompiled_dir so a directory literally named 'smali' or
        'sources' higher up in an absolute path can't be mistaken for the source root.
        Returns None if the path is not under a recognized source root.
        """
        normalized = file_path.replace("\\", "/")

        # Strip the decompiled_dir prefix so the first remaining segment is the root.
        base = self.decompiled_dir.replace("\\", "/").rstrip("/")
        if normalized.startswith(base + "/"):
            normalized = normalized[len(base) + 1:]

        # Strip the source extension.
        for ext in (".smali", ".java"):
            if normalized.endswith(ext):
                normalized = normalized[:-len(ext)]
                break
        else:
            return None

        parts = normalized.split("/")
        if len(parts) < 2:
            return None

        root = parts[0]
        if root == "sources" or root == "smali" or root.startswith("smali_classes"):
            return "/".join(parts[1:])
        return None

    def get_dependencies(self, file_path: str) -> list:
        """
        Returns the normalized class names that the given file depends on (calls).

        The call graph is always built from Smali (bytecode ground-truth), but the
        file being analyzed may be a Java path (JADX/hybrid mode) — so we resolve the
        target via path_to_class() instead of an exact path match. JADX bundles inner
        classes into the parent .java file, so we also aggregate callees from the
        target's inner classes (Foo, Foo$Bar, Foo$1, ...).
        """
        target_class = self.path_to_class(file_path)
        if not target_class:
            return []

        def _belongs_to_target(cls: str) -> bool:
            # The target class itself or one of its inner classes.
            return cls == target_class or cls.startswith(target_class + "$")

        dependency_classes = set()
        for cls, callees in self.call_graph.items():
            if not _belongs_to_target(cls):
                continue
            for callee_class, _ in callees:
                # Keep only resolvable, non-self dependencies.
                if callee_class in self.class_to_file and not _belongs_to_target(callee_class):
                    dependency_classes.add(callee_class)

        return list(dependency_classes)
