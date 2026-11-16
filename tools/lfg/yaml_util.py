"""YAML loader shared by the spec and template loaders: rejects duplicate mapping keys."""

import yaml


class UniqueKeyLoader(yaml.SafeLoader):
    """A SafeLoader that raises on a repeated key, at any nesting depth.

    A duplicated key lets a file show one value to a reader and another to the checker.
    """

    def construct_mapping(self, node, deep=False):
        if isinstance(node, yaml.MappingNode):
            seen = set()
            for key_node, _ in node.value:
                try:
                    key = self.construct_object(key_node, deep=True)
                    hash(key)
                except TypeError:
                    continue
                if key in seen:
                    raise yaml.constructor.ConstructorError(
                        None, None, f"duplicate key {key!r}", key_node.start_mark
                    )
                seen.add(key)
        return super().construct_mapping(node, deep=deep)
