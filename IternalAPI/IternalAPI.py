from .APIEnum import IternalAPIEnum


class IternalAPI:
    @staticmethod
    def get_api(api):
        return IternalAPIEnum[api].value
