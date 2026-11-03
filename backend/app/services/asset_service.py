"""Normalized asset inventory and history queries."""

import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlsplit

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import Asset, Investigation


def _database_time(value):
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def normalize_asset_target(target: str) -> tuple[str, str, str]:
    value = (target or "").strip()
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    host = (parsed.hostname or value).rstrip(".").lower()
    try:
        host = ipaddress.ip_address(host).compressed
        kind = "ip"
    except ValueError:
        kind = "domain"
    return host, host, kind


def get_or_create_asset(db: Session, target: str, seen_at=None) -> Asset:
    key, canonical, kind = normalize_asset_target(target)
    seen_at = _database_time(seen_at or datetime.now(timezone.utc))
    asset = db.query(Asset).filter(Asset.target_key == key).first()
    if asset is None:
        asset = Asset(
            target_key=key,
            canonical_target=canonical,
            target_type=kind,
            first_seen_at=seen_at,
            last_seen_at=seen_at,
        )
        db.add(asset)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            asset = db.query(Asset).filter(Asset.target_key == key).first()
            if asset is None:
                raise
    if asset.first_seen_at is None or seen_at < _database_time(asset.first_seen_at):
        asset.first_seen_at = seen_at
    if asset.last_seen_at is None or seen_at > _database_time(asset.last_seen_at):
        asset.last_seen_at = seen_at
    db.flush()
    return asset


def list_assets(db: Session, skip: int = 0, limit: int = 50) -> tuple[list[tuple[Asset, int]], int]:
    total = db.query(Asset).count()
    rows = (
        db.query(Asset, func.count(Investigation.id).label("scan_count"))
        .outerjoin(Investigation, Investigation.asset_id == Asset.id)
        .group_by(Asset.id)
        .order_by(Asset.last_seen_at.desc(), Asset.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [(asset, count) for asset, count in rows], total


def asset_history(db: Session, asset_id: int, skip: int = 0, limit: int = 20):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if asset is None:
        return None, [], 0
    query = db.query(Investigation).filter(Investigation.asset_id == asset_id)
    total = query.count()
    rows = query.order_by(Investigation.created_at.desc(), Investigation.id.desc()).offset(skip).limit(limit).all()
    return asset, rows, total
