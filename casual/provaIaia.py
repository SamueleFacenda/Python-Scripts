import os
from iaia import InfiniteAIArray
import iaia
# set OPENAAI_API_KEY environment variable to your API key
# or use set_gpt_key() to set it for this session
os.environ["OPENAAI_API_KEY"] = "sk-..."
iaia.set_gpt_key("sk-...")

pokemons = InfiniteAIArray()
print(pokemons[:20])