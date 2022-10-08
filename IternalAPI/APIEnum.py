from enum import Enum
from .Modules.GET_ID import GET_ID
from .Modules.GET_INFO import GET_INFO
from .Modules.SEND_MESSAGE import SEND_MESSAGE


class IternalAPIEnum(Enum):
    GET_ID = GET_ID
    GET_INFO = GET_INFO
    SEND_MESSAGE = SEND_MESSAGE
