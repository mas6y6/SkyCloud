
PERMISSIONS = {
    "READ": 0,
    "WRITE": 1,
    "DELETE": 2,
    "ADMIN": 4,
}

class Permissions:
    def __init__(self, bitfield=0):
        self.bitfield = bitfield

    def add_permission(self, permission):
        if permission in PERMISSIONS:
            self.bitfield |= (1 << PERMISSIONS[permission])
        else:
            raise ValueError(f"Invalid permission: {permission}")

    def remove_permission(self, permission):
        if permission in PERMISSIONS:
            self.bitfield &= ~(1 << PERMISSIONS[permission])
        else:
            raise ValueError(f"Invalid permission: {permission}")

    def has_permission(self, permission):
        if permission in PERMISSIONS:
            return bool(self.bitfield & (1 << PERMISSIONS[permission]))
        else:
            raise ValueError(f"Invalid permission: {permission}")

    def list_permissions(self):
        return [perm for perm, bit in PERMISSIONS.items() if self.bitfield & (1 << bit)]
