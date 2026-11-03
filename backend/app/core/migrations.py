"""Small, additive schema upgrades for installations predating asset inventory."""

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from ..models import Asset, Base, Investigation
from ..services.asset_service import normalize_asset_target


def initialize_schema(engine) -> None:
    """Create new tables and add/backfill the nullable asset link without dropping rows."""
    Base.metadata.create_all(bind=engine)
    columns = {column["name"] for column in inspect(engine).get_columns("investigations")}
    if "asset_id" not in columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE investigations ADD COLUMN asset_id INTEGER REFERENCES assets(id)"))
    if "risk_evidence_status" not in columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE investigations ADD COLUMN risk_evidence_status VARCHAR(30)"))
    with engine.begin() as connection:
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_investigations_asset_id ON investigations(asset_id)"))
    with Session(engine) as session:
        investigations = session.query(Investigation).order_by(Investigation.created_at, Investigation.id).all()
        assets_by_key = {asset.target_key: asset for asset in session.query(Asset).all()}
        for investigation in investigations:
            key, canonical, target_type = normalize_asset_target(investigation.target)
            asset = assets_by_key.get(key)
            stamp = investigation.created_at
            if stamp is None:
                stamp = investigation.updated_at
            if stamp is not None and stamp.tzinfo is not None:
                stamp = stamp.replace(tzinfo=None)
            if asset is None:
                asset = Asset(
                    target_key=key,
                    canonical_target=canonical,
                    target_type=target_type,
                    first_seen_at=stamp,
                    last_seen_at=stamp,
                )
                session.add(asset)
                session.flush()
                assets_by_key[key] = asset
            elif stamp:
                if asset.first_seen_at is None or stamp < asset.first_seen_at:
                    asset.first_seen_at = stamp
                if asset.last_seen_at is None or stamp > asset.last_seen_at:
                    asset.last_seen_at = stamp
            if investigation.asset_id is None:
                investigation.asset_id = asset.id
        session.commit()
