from unittest.mock import Mock


class AsyncMock(Mock):
    async def __call__(self, *args, **kwargs):
        result = super().__call__(*args, **kwargs)
        return result
