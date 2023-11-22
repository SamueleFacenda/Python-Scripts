from datetime import datetime
from abc import ABC, abstractmethod
from sqlalchemy import ForeignKey, String, create_engine, select, or_
from sqlalchemy.orm import DeclarativeBase, Mapped, relationship, mapped_column, sessionmaker, scoped_session
from typing import Optional, List, Set, Tuple
from sqlalchemy.pool import StaticPool
from sqlalchemy import event
from threading import Lock
from icecream import ic


class Base(DeclarativeBase):
    pass

class Player(Base):
    __tablename__ = "player"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False, unique=True, index=True)
    matches: Mapped[List["Match"]] = relationship(primaryjoin="or_(Player.id==Match.one_id, Player.id==Match.two_id)" , cascade="all, delete-orphan") 

    def __init__(self, name):
        super().__init__(name=name)

    @staticmethod
    def get_or_create(persistency, name):
        raise Exception(f"Creating players is not supported anymore: {name=}")
        persistency.session.close()
        stmt = select(Player).where(Player.name == name).limit(1)
        player = persistency.session.scalar(stmt)
        persistency.session.close()
        if player is None:
            player = Player(name)
            with persistency.session() as session:
                session.add(player)
                session.commit()
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
    one: Mapped["Player"] = relationship("Player", foreign_keys=[one_id], overlaps="matches")
    two: Mapped["Player"] = relationship("Player", foreign_keys=[two_id], overlaps="matches")

    def __init__(self, one: "Player", two: "Player", score: list[Tuple[int, int]], event: "TTEvent"=None):
        super().__init__(one=one, two=two, score=score, event=event)

    def __repr__(self):
        return f"<Match {self.one} vs {self.two} {self.score}>"

    @staticmethod
    def get_all(persistency):
        with persistency.session() as session:
            return session.query(Match).all()

    @staticmethod
    def persist_all(persistency, matches):
        # check if type is correct
        for match in matches:
            if not isinstance(match, Match):
                raise TypeError(f"Expected Match, got {type(match)}, {match=}")
        with persistency.session() as session:
            session.add_all(matches)
            session.commit()
            # wait for the transaction to be committed
            matches[0].id


class TTEvent(Base):
    __tablename__ = "event"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    date: Mapped[datetime | None]
    matches: Mapped[List["Match"]] = relationship(back_populates="event", cascade="all, delete-orphan")

    def __init__(self, name, date=None):
        super().__init__(name=name, date=date)
        
    @staticmethod
    def get_or_create(persistency, name, date=None):
        with persistency.session() as session:
            stmt = select(TTEvent).where(TTEvent.name == name).limit(1)
            event = session.scalar(stmt)

        if event is None:
            event = TTEvent(name, date)
            with persistency.session() as session:
                session.add(event)
                session.commit()
        return event
        

    @staticmethod
    @abstractmethod
    def getName(a, b):
        raise NotImplementedError

    @staticmethod
    def exists(persistency, name):
        with persistency.session() as session:
            stmt = select(TTEvent).where(TTEvent.name == name).limit(1)
            return session.execute(stmt).first() is not None


    def __repr__(self):
        return f"<TTEvent {self.name} {self.date}>"


class ABTTEvent(TTEvent):
    @classmethod
    def get_or_create(cls, persistency, a, b, date=None):
        name = cls.getName(a, b)
        return super().get_or_create(persistency, name, date)

    @classmethod
    def exists(cls, persistency, a, b):
        name = cls.getName(a, b)
        return super().exists(persistency, name)

class Tournament(ABTTEvent):
    @staticmethod
    def getName(id, reg):
        return f"torneo-{id}-{reg}"

class ChampionshipMatch(ABTTEvent):
    @staticmethod
    def getName(camp, inc):
        return f"partita-{camp}-{inc}"

class Persistency:
    def __init__(self, path):
        self.engine = create_engine("sqlite://", echo=False, connect_args={'check_same_thread': False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(self.engine)
        self.Session = scoped_session(self.Session)

        #@event.listens_for(self.Session, 'before_flush')
        def add_players_references(session, flush_context, instances):
            new_players: Dict[str, Player] = {}
            for instance in session.new:
                if isinstance(instance, Match):
                    players = []
                    for name in [instance.one.name, instance.two.name]:
                        if name in new_players:
                            player = new_players[name]
                        else:
                            stmt = select(Player).where(Player.name == name).limit(1)
                            player = session.execute(stmt).first()
                            if player is None:
                                # cascade save-update
                                player = Player(name)
                            new_players[name] = player
                        players.append(player)
                    instance.one, instance.two = players

    @property
    def session(self):scoped_session
        return self.Session

    def get_all_matches(self):
        return Match.get_all(self)

    def get_all_event_names(self):
        return set(self.session.query(TTEvent).all())
