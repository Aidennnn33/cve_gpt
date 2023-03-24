class APIError(Exception):
    
    def __init_(self, value):
        self.value = value

class APITimeout(APIError):
    pass