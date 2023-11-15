from datetime import datetime
from abc import ABC, abstractmethod

class Player:
    def __init__(self, name):
        self.name: str = name
        self.matches: set["Match"] = set()
        # print(f"Created player {name}")

    instances: dict[str, "Player"] = {}

    @staticmethod
    def get(name) -> "Player":
        name = name.strip().title()
        if name in Player.instances:
            return Player.instances[name]
        else:
            Player.instances[name] = Player(name)
            return Player.instances[name]    

class Match:
    def __init__(self, one, two, score: list[tuple[int, int]], event=None):
        self.one: Player = one
        self.two: Player = two
        self.score: list[tuple[int, int]] = score
        
        self.one.matches.add(self)
        self.two.matches.add(self)

        self.event = event

    @property
    def event(self):
        return self._event

    @event.setter
    def event(self, value):
        self._event = value
        if value:
            self._event.matches.add(self)

    def __str__(self):
        return f"{self._event.date.strftime('%d/%m/%Y')}: {self.one.name} vs {self.two.name} with score {self.score}"

    def serialize(self):
        return {
            "one": self.one.name, 
            "two": self.two.name, 
            "score": self.score,
            "source": self._event.serialize() }

    @staticmethod
    def deserialize(data):
        return Match(
            Player.get(data["one"]), 
            Player.get(data["two"]), 
            [tuple(x) for x in data["score"]], 
            ABTTEvent.deserialize(data["source"]))

    #def __hash__(self):
    #    return hash((self.one.name, self.two.name, tuple(self.score)))#, self._source.name))#, self.date) TODO

class TTEvent(ABC):
    instances: dict[str, "TTEvent"] = {}

    def __init__(self, name, date):
        self.name: str = name
        self.date: datetime = date
        self.matches: set["Match"] = set()
        
    @classmethod 
    def get(cls, name, date=None):
        if name not in TTEvent.instances:
            TTEvent.instances[name] = cls(name, date)

        return TTEvent.instances[name]

    @staticmethod
    @abstractmethod
    def getName(a, b):
        raise NotImplementedError

    @classmethod 
    def exists(cls, name):
        return name in TTEvent.instances

    @abstractmethod
    def serialize(self):
        raise NotImplementedError

    @staticmethod
    def deserialize(data):
        raise NotImplementedError


class ABTTEvent(TTEvent, ABC):
    @classmethod
    def get(cls, a, b, date=None):
        name = cls.getName(a, b)
        return super().get(name, date)

    @classmethod
    def exists(cls, a, b):
        name = cls.getName(a, b)
        return name in TTEvent.instances

    def serialize(self):
        tipe, a, b = self.name.split("-")
        date = self.date.strftime("%d/%m/%Y") if self.date else None
        return {"type": tipe, "a": a, "b": b, "date": date} 

    @staticmethod
    def deserialize(data):
        cls = {"torneo": Tournament, "partita": ChampionshipMatch}[data["type"]]
        date = datetime.strptime(data["date"], "%d/%m/%Y") if "date" in data else None
        return cls.get(data["a"], data["b"], date)


class Tournament(ABTTEvent):
    @staticmethod
    def getName(id, reg):
        return f"torneo-{id}-{reg}"

class ChampionshipMatch(ABTTEvent):
    @staticmethod
    def getName(camp, inc):
        return f"partita-{camp}-{inc}"