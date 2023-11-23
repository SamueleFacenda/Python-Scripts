from datetime import datetime
from abc import ABC, abstractmethod
from sqlalchemy import ForeignKey, String, create_engine, select, or_, event
from sqlalchemy.orm import DeclarativeBase, Mapped, relationship, mapped_column, sessionmaker, scoped_session
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
    # TODO remove lazy joined, or extend this to all the other relationships
    matches: Mapped[List["Match"]] = relationship(primaryjoin="or_(Player.id==Match.one_id, Player.id==Match.two_id)" , cascade="merge, delete, expunge, delete-orphan", lazy='joined') 

    def __init__(self, name):
        super().__init__(name=name)

    @staticmethod
    def get(persistency, name):
        with persistency.session.begin():
            stmt = select(Player).where(Player.name == name).limit(1)
            player = persistency.session.scalar(stmt)
        if player is None:
            raise ValueError(f"Player {name} not found")
        return player

    @staticmethod
    def get_player_matches(persistency, name):
        # TODO does not work, maybe is the primaryjoin or the strange loading hook
        player = Player.get(persistency, name)
        with persistency.session.begin():
            return player.matches

    def __repr__(self):
        return f"<Player {self.name}>"

class Match(Base):
    __tablename__ = "match"
    id: Mapped[int] = mapped_column(primary_key=True)
    one_id: Mapped[int] = mapped_column(ForeignKey("player.id"))
    two_id: Mapped[int] = mapped_column(ForeignKey("player.id"))
    _score: Mapped[str] = mapped_column(String(80))
    event_id: Mapped[int] = mapped_column(ForeignKey("event.id"))
    event: Mapped["TTEvent"] = relationship(back_populates="matches", cascade="merge, expunge", lazy='select')
    one: Mapped["Player"] = relationship("Player", foreign_keys=[one_id], overlaps="matches", cascade="merge")
    two: Mapped["Player"] = relationship("Player", foreign_keys=[two_id], overlaps="matches", cascade="merge")

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
            # wait for the transaction to be committed, now trying without this
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
    def getName(a, b):
        raise NotImplementedError

    def __repr__(self):
        return f"<TTEvent {self.name} {self.date}>"


class ABTTEvent(TTEvent):
    def __init__(self, a, b, date=None):
        super().__init__(self.getName(a, b), date)

class Tournament(ABTTEvent):
    @staticmethod
    def getName(id, reg):
        return f"torneo-{id}-{reg}"

class ChampionshipMatch(ABTTEvent):
    @staticmethod
    def getName(camp, inc):
        return f"partita-{camp}-{inc}"

def find_or_create_by_name(session, name, Obj_class, cached_results, **kwargs):
    #ic("Ask for ", name)
    if name in cached_results:
        return cached_results[name]
    stmt = select(Obj_class).where(Obj_class.name == name).limit(1)
    obj = session.scalar(stmt)
    if obj is None:
        obj = Obj_class(name, **kwargs)
        session.add(obj)
        # TODO remove this
        #ic("Created ", obj)
    #else:
        #ic("Found ", obj)
    cached_results[name] = obj
    return obj

class Persistency:
    def __init__(self, path):
        self.engine = create_engine("sqlite://", echo=False, connect_args={'check_same_thread': False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(self.engine, autobegin=False)
        self.Session = scoped_session(self.Session)

        @event.listens_for(self.Session, 'before_flush')
        def add_players_references(session, flush_context, instances):
            new_players: Dict[str, Player] = {}
            new_events: Dict[str, TTEvent] = {}
            for instance in [ x for x in session.new if isinstance(x, Match) ]:
                instance.one = find_or_create_by_name(session, instance.one.name, Player, new_players)
                instance.two = find_or_create_by_name(session, instance.two.name, Player, new_players)
                instance.event = find_or_create_by_name(session, instance.event.name, TTEvent, new_events, date=instance.event.date)
            #ic(session.new)

            # SAWarning: Object of type <Match> not in session, add operation along 'TTEvent.matches' will not proceed
            # TODO understand why this happens
            problem = False
            for event in new_events.values():
                for match in event.matches:
                    if match not in session.new:
                        ic("Match not in session.new", match)
                        problem = True
            if problem:
                ic("session.new", session.new)


    @property
    def session(self):
        return self.Session

    def get_all_matches(self):
        return Match.get_all(self)

    def get_all_event_names(self):
        with self.session.begin():
            stmt = select(TTEvent.name).distinct()
            return set(self.session.scalars(stmt))