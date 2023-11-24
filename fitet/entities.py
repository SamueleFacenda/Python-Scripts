from datetime import datetime
from abc import ABC, abstractmethod
from sqlalchemy import ForeignKey, String, create_engine, select, or_, event, Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, relationship, mapped_column, sessionmaker, scoped_session, object_session
from typing import Optional, List, Set, Tuple
from sqlalchemy.pool import StaticPool
from threading import Lock
from icecream import ic


class Base(DeclarativeBase):
    pass

class Player(Base):
    __tablename__ = "player"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    # TODO think about lazy='selectin'
    matches: Mapped[List["Match"]] = relationship(primaryjoin="or_(Player.id==Match.one_id, Player.id==Match.two_id)" , cascade="merge, delete, expunge, delete-orphan", lazy='select', viewonly=True) 

    def __init__(self, name):
        super().__init__(name=name)

    @staticmethod
    def get(persistency, name):
        stmt = select(Player).where(Player.name == name).limit(1)
        player = persistency.session.scalar(stmt)
        if player is None:
            raise ValueError(f"Player {name} not found")
        return player

    def __repr__(self):
        return f"<Player {self.name}>"

    def pretty_str(self)->str:
        out = '#'*(len(self.name)+6) + '\n'
        out += '## ' + self.name + ' ##\n'
        out += '#'*(len(self.name)+6) + '\n'
        out += '\n'.join([str(x) for x in self.matches])
        out += '\n'
        return out
class Match(Base):
    __tablename__ = "match"
    id: Mapped[int] = mapped_column(primary_key=True)
    one_id: Mapped[int] = mapped_column(ForeignKey("player.id"))
    two_id: Mapped[int] = mapped_column(ForeignKey("player.id"))
    _score: Mapped[str] = mapped_column(String(80))
    event_id: Mapped[int] = mapped_column(ForeignKey("event.id"))
    event: Mapped["TTEvent"] = relationship(back_populates="matches", cascade="merge", lazy='joined')
    one: Mapped["Player"] = relationship("Player", foreign_keys=[one_id], cascade="merge", lazy='joined')
    two: Mapped["Player"] = relationship("Player", foreign_keys=[two_id], cascade="merge", lazy='joined')

    def __init__(self, one: "Player", two: "Player", score: list[Tuple[int, int]], event: "TTEvent"=None):
        super().__init__(one=one, two=two, score=score, event=event)

    @property
    def score(self):
        return eval(self._score)# 😬😬😬😬

    @score.setter
    def score(self, value):
        self._score = repr(value)

    def __repr__(self):
        return f"<Match {self.one} vs {self.two} {self.score}>"

    def __str__(self):
        return f"{self.event.date}: {self.one.name} vs {self.two.name} {self.score}"

    @staticmethod
    def get_all(persistency):
        with persistency.session.begin():
            return persistency.session.query(Match).all()

    @staticmethod
    def persist_all(persistency, matches):
        # check if type is correct
        for match in matches:
            if not isinstance(match, Match):
                raise TypeError(f"Expected Match, got {type(match)}, {match=}")
        with persistency.session.begin():
            persistency.session.add_all(matches)
            # wait for the transaction to be committed
            if len(matches): matches[0].id


class TTEvent(Base):
    __tablename__ = "event"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    date: Mapped[datetime | None]
    matches: Mapped[List["Match"]] = relationship(back_populates="event", cascade="merge, delete, expunge, delete-orphan")

    def __init__(self, name, date=None):
        super().__init__(name=name, date=date)
        
    @staticmethod
    @abstractmethod
    def get_name(a, b):
        raise NotImplementedError

    def __repr__(self):
        return f"<TTEvent {self.name} {self.date}>"

    @staticmethod
    def get_all_names(persistency):
        with persistency.session.begin():
            stmt = select(TTEvent.name).distinct()
            return set(persistency.session.scalars(stmt))


class ABTTEvent(TTEvent):
    def __init__(self, a, b, date=None):
        super().__init__(self.get_name(a, b), date)

class Tournament(ABTTEvent):
    @staticmethod
    def get_name(id, reg):
        return f"torneo-{id}-{reg}"

class ChampionshipMatch(ABTTEvent):
    @staticmethod
    def get_name(camp, inc):
        return f"partita-{camp}-{inc}"

def find_or_create_by_name(session, name, Obj_class, cached_results, **kwargs):
    if name in cached_results:
        return cached_results[name]
    stmt = select(Obj_class).where(Obj_class.name == name).limit(1)
    obj = session.scalar(stmt)
    if obj is None:
        obj = Obj_class(name, **kwargs)
        session.add(obj)
    cached_results[name] = obj
    return obj

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

class Persistency:
    def __init__(self, path):
        self.engine = create_engine(f"sqlite:///{path}", echo=False)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(self.engine, autobegin=True)
        self.Session = scoped_session(self.Session)

        @event.listens_for(self.Session, 'before_flush')
        def add_players_references(session, flush_context, instances):
            # use references to players instead of creating new ones
            new_players: Dict[str, Player] = {}
            new_events: Dict[str, TTEvent] = {}
            for instance in [x for x in session.new if isinstance(x, Match)]:
                instance.one = find_or_create_by_name(session, instance.one.name, Player, new_players)
                instance.two = find_or_create_by_name(session, instance.two.name, Player, new_players)
                instance.event = find_or_create_by_name(session, instance.event.name, TTEvent, new_events, date=instance.event.date)


    @property
    def session(self):
        return self.Session

    def get_all_matches(self):
        return Match.get_all(self)

    def get_all_event_names(self):
        with self.session.begin():
            stmt = select(TTEvent.name).distinct()
            return set(self.session.scalars(stmt))