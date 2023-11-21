from datetime import datetime
from abc import ABC, abstractmethod
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped, relationship, mapped_column, sessionmaker
from typing import Optional, List, Set, Tuple
from sqlalchemy import create_engine

engine = create_engine("sqlite://", echo=True)
Session = sessionmaker(engine)

class Base(DeclarativeBase):
    pass

# decorator
def add_to_session(func):
    def wrapper(self, *args, **kwargs):
        with Session().begin() as session:
            out = func(self, *args, **kwargs)
            session.add(self)
            return out
    return wrapper

# to be used with "with" statement
def update_persistency(func):
    return Session().begin()


class Player(Base):
    __tablename__ = "player"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False, unique=True, index=True)
    matches: Mapped[List["Match"]] = relationship(foreign_keys="[Match.one_id, Match.two_id]", back_populates="players", cascade="all, delete-orphan") 

    # @add_to_session
    def __init__(self, name):
        super().__init__(name=name)

    @staticmethod
    def get_or_create(name):
        with Session().begin() as session:
            player = session.query(Player).filter_by(name=name).first()
            if player is None:
                player = Player(name)
                session.add(player)
        return player

    def __repr__(self):
        return f"<Player {self.name}>"

class Match(Base):
    __tablename__ = "match"
    id: Mapped[int] = mapped_column(primary_key=True)
    one_id: Mapped[int] = mapped_column(ForeignKey("player.id"), nullable=False)
    two_id: Mapped[int] = mapped_column(ForeignKey("player.id"), nullable=False)
    score: Mapped[list[Tuple[int, int]]] = mapped_column(String(80), nullable=False)
    event_id: Mapped[int] = mapped_column(ForeignKey("event.id"), nullable=False)
    event: Mapped["TTEvent"] = relationship(back_populates="matches")
    players: Mapped[List["Player"]] = relationship(foreign_keys=[one_id, two_id], back_populates="matches")

    # @add_to_session
    def __init__(self, one: "Player", two: "Player", score: list[Tuple[int, int]], event: "TTEvent"):
        super().__init__(one=one, two=two, score=score, event=event)

    def __repr__(self):
        return f"<Match {self.one} vs {self.two} {self.score}>"

    @staticmethod
    def get_all():
        with Session() as session:
            out = session.query(Match).all()
        return out

    @staticmethod
    def persist_all(matches):
        with Session().begin() as session:
            session.add_all(matches)

class TTEvent(Base):
    __tablename__ = "event"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    date: Mapped[datetime | None]
    matches: Mapped[List["Match"]] = relationship(back_populates="event", cascade="all, delete-orphan")

    # @add_to_session
    def __init__(self, name, date=None):
        super().__init__(name=name, date=date)
        
    @classmethod
    def get_or_create(cls, name, date=None):
        with Session().begin() as session:
            event = session.query(TTevent).filter_by(name=name).first()
            if event is None:
                event = cls(name=name, date=date)
                session.add(event)
        return event
        

    @staticmethod
    @abstractmethod
    def getName(a, b):
        raise NotImplementedError

    @staticmethod
    def exists(name):
        with Session(engine) as session:
            return session.query(TTevent).filter_by(name=name).first() is not None

    def __repr__(self):
        return f"<TTEvent {self.name} {self.date}>"


class ABTTEvent(TTEvent):
    @classmethod
    def get_or_create(cls, a, b, date=None):
        name = cls.getName(a, b)
        return super().get_or_create(name, date)

    @classmethod
    def exists(cls, a, b):
        name = cls.getName(a, b)
        return super().exists(name)

class Tournament(ABTTEvent):
    @staticmethod
    def getName(id, reg):
        return f"torneo-{id}-{reg}"

class ChampionshipMatch(ABTTEvent):
    @staticmethod
    def getName(camp, inc):
        return f"partita-{camp}-{inc}"

Base.metadata.create_all(engine)
