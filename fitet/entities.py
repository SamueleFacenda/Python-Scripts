from fitet.threadutils import WaitableThreadPool
from datetime import datetime, timedelta

class Player:
    def __init__(self, name):
        self.name: str = name
        self.matches: set["Match"] = set()
        # print(f"Created player {name}")

    instances: dict[str, "Player"] = {}
    def get(name) -> "Player":
        name = name.strip().title()
        if name in Player.instances:
            return Player.instances[name]
        else:
            Player.instances[name] = Player(name)
            return Player.instances[name]    

class Match:
    def __init__(self, one, two, score: list[tuple[int, int]], source=None, date=None):
        self.one: Player = one
        self.two: Player = two
        self.score: list[tuple[int, int]] = score
        self.date = date
        
        self.one.matches.add(self)
        self.two.matches.add(self)

        self._source = source
        if source:
            self._source.matches.add(self)

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, value):
        self._source = value
        self._source.matches.add(self)

    def __str__(self):
        return f"{self.date.strftime('%d/%m/%Y')}: {self.one.name} vs {self.two.name} with score {self.score}"

    def serialize(self):
        return {"one": self.one.name, "two": self.two.name, "score": self.score, "date": self.date.strftime('%d/%m/%Y'), "source": self._source.name }

    def deserialize(data):
        return Match(Player.get(data["one"]), Player.get(data["two"]), [tuple(x) for x in data["score"]], MatchSource.get(data["source"]), datetime.strptime(data["date"], "%d/%m/%Y"))

    def __hash__(self):
        return hash((self.one.name, self.two.name, tuple(self.score)))#, self._source.name))#, self.date)

class MatchSource:
    instances: dict[str, "MatchSource"] = {}

    def __init__(self, name):
        self.name: str = name
        self.matches: set["Match"] = set()
        
    def get(name):
        if name not in MatchSource.instances:
            MatchSource.instances[name] = MatchSource(name)

        return MatchSource.instances[name]

    def _nameTrn(id, reg):
        return f"torneo-{id}-{reg}"

    def _nameChmp(camp, inc):
        return f"partita-{camp}-{inc}"

    def getFromTorneo(id, reg):
        name = MatchSource._nameTrn(id, reg)
        return MatchSource.get(name)

    def getFromPartitaCampionato(camionato, incontro):
        name = MatchSource._nameChmp(camionato, incontro)
        return MatchSource.get(name)

    def existsTorneo(id, reg):
        name = MatchSource._nameTrn(id, reg)
        return name in MatchSource.instances

    def existsPartitaCampionato(camionato, incontro):
        name = MatchSource._nameChmp(camionato, incontro)
        return name in MatchSource.instances