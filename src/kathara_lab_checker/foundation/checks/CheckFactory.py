import importlib
import inspect
import pkgutil

from .AbstractCheck import AbstractCheck


class CheckFactory:
    @staticmethod
    def instantiate_classes_from_package_name(package_name, lab) -> list[AbstractCheck]:
        instances = []
        package = importlib.import_module(package_name)

        def process_package(pkg):
            """ Recursively process all modules and sub-packages """
            for finder, module_name, is_pkg in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
                module = importlib.import_module(module_name)

                if is_pkg:
                    process_package(module)  # Recursively process sub-packages
                else:
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if obj.__module__ == module.__name__:
                            try:
                                instances.append(obj(lab))
                            except TypeError as e:
                                print(f"Skipping {obj.__name__}: {e}")

        process_package(package)
        return instances
