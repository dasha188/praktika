import os
import logging
from datetime import datetime, timedelta, UTC
from uuid import uuid4
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import BasicConstraints, CRLReason, ReasonFlags
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Text, DateTime, Integer, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session
import subprocess
import OpenSSL.crypto as crypto

app = FastAPI(title="Система управления цифровыми сертификатами", version="1.0")

class Settings:
    DB_URL = "postgresql://postgres:1234@localhost:5432/pki"
    HSM_MODULE = "C:\\SoftHSM2\\lib\\softhsm2.dll"
    HSM_PIN = "1234"
    CA_KEY_LABEL = "ca_key"
    OCSP_KEY_LABEL = "ocsp_key"

settings = Settings()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

Base = declarative_base()

class Certificate(Base):
    __tablename__ = 'certificates'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    serial_number = Column(String(64), unique=True)
    common_name = Column(String(255))
    status = Column(String(20), default="VALID")
    certificate_pem = Column(Text)
    private_key_pem = Column(Text)
    issued_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    revoked_at = Column(DateTime, nullable=True)
    revocation_reason = Column(String(100), nullable=True)

class CRLEntry(Base):
    __tablename__ = 'crl_entries'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    serial_number = Column(String(64))
    revocation_date = Column(DateTime, default=datetime.utcnow)
    reason = Column(String(100))

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(100), nullable=False)
    user = Column(String(50), default="admin")
    target = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean, default=True)

engine = create_engine(settings.DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class HSMClient:
    def __init__(self):
        self.keys = {}

    def generate_keypair(self, label: str):
        # Генерация через OpenSSL CLI
        key_path = f"/tmp/{label}_key.pem"
        subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True)
        with open(key_path, "rb") as f:
            key_data = f.read()
        os.remove(key_path)
        private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)
        return private_key.to_cryptography_key().public_key(), private_key.to_cryptography_key()

    def get_keypair(self, label: str):
        private_key = self.keys.get(label)
        if private_key:
            return private_key.to_cryptography_key().public_key(), private_key.to_cryptography_key()
        return None, None

hsm_client = HSMClient()

def initialize_ca():
    # Создаём ключ через CLI
    ca_key_path = "/tmp/ca_key.pem"
    subprocess.run(["openssl", "genrsa", "-out", ca_key_path, "2048"], check=True)
    with open(ca_key_path, "rb") as f:
        ca_key_pem = f.read()
    os.remove(ca_key_path)

    ca_key_crypto = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_pem)
    ca_cert_crypto = crypto.X509()
    ca_cert_crypto.get_subject().C = "RU"
    ca_cert_crypto.get_subject().O = "My PKI CA"
    ca_cert_crypto.get_subject().CN = "Root CA"
    ca_cert_crypto.set_serial_number(int(uuid4().int))
    ca_cert_crypto.gmtime_adj_notBefore(0)
    ca_cert_crypto.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)  # 10 лет
    ca_cert_crypto.set_issuer(ca_cert_crypto.get_subject())
    ca_cert_crypto.set_pubkey(ca_key_crypto)
    ca_cert_crypto.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:true, pathlen:0")
    ])
    ca_cert_crypto.sign(ca_key_crypto, 'sha256')

    # Сохраняем в cryptography-объект
    ca_cert_crypto_bytes = crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert_crypto)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_crypto_bytes, default_backend())

    hsm_client.keys[settings.CA_KEY_LABEL] = ca_key_crypto
    return ca_cert

ca_cert = initialize_ca()

class CertificateRequest(BaseModel):
    common_name: str
    organization: str = "My Organization"
    country: str = "RU"
    validity_days: int = 365

class RevokeRequest(BaseModel):
    serial_number: str
    reason: str = "unspecified"

class OCSPRequest(BaseModel):
    serial_number: str

@app.post("/certificates/issue")
async def issue_certificate(
        request: CertificateRequest,
        db: Session = Depends(get_db)
):
    try:
        # Генерация ключа через CLI
        key_path = f"/tmp/cert_key_{uuid4()}.pem"
        subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True)
        with open(key_path, "rb") as f:
            key_pem = f.read()
        os.remove(key_path)

        key_crypto = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)
        csr_crypto = crypto.X509Req()
        csr_crypto.get_subject().C = request.country
        csr_crypto.get_subject().O = request.organization
        csr_crypto.get_subject().CN = request.common_name
        csr_crypto.set_pubkey(key_crypto)
        csr_crypto.sign(key_crypto, 'sha256')

        # Подписываем CSR с помощью CA
        cert_crypto = crypto.X509()
        cert_crypto.set_subject(csr_crypto.get_subject())
        cert_crypto.set_serial_number(int(uuid4().int))
        cert_crypto.gmtime_adj_notBefore(0)
        cert_crypto.gmtime_adj_notAfter(request.validity_days * 24 * 60 * 60)
        cert_crypto.set_issuer(ca_cert.subject)
        cert_crypto.set_pubkey(csr_crypto.get_pubkey())

        # Подписываем сертификат
        ca_key = hsm_client.get_keypair(settings.CA_KEY_LABEL)[1]._private_key
        ca_key_crypto = crypto.PKey.from_cryptography_key(ca_key)
        cert_crypto.sign(ca_key_crypto, 'sha256')

        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert_crypto).decode()
        serial = str(cert_crypto.get_serial_number())

        cert_record = Certificate(
            serial_number=serial,
            common_name=request.common_name,
            certificate_pem=cert_pem,
            private_key_pem=key_pem.decode(),
            expires_at=datetime.now(UTC) + timedelta(days=request.validity_days)
        )
        db.add(cert_record)
        db.commit()

        return {
            "serial_number": serial,
            "certificate": cert_pem,
            "status": "ISSUED"
        }

    except Exception as e:
        db.rollback()
        logger.error(f"Certificate issuance failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Certificate issuance failed"
        )

@app.post("/certificates/revoke")
async def revoke_certificate(
        request: RevokeRequest,
        db: Session = Depends(get_db)
):
    try:
        cert = db.query(Certificate).filter(
            Certificate.serial_number == request.serial_number
        ).first()

        if not cert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Certificate not found"
            )

        if cert.status == "REVOKED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Certificate already revoked"
            )

        cert.status = "REVOKED"
        cert.revoked_at = datetime.now(UTC)
        cert.revocation_reason = request.reason

        crl_entry = CRLEntry(
            serial_number=request.serial_number,
            reason=request.reason
        )
        db.add(crl_entry)
        db.commit()

        return {"status": "REVOKED", "serial_number": request.serial_number}

    except Exception as e:
        db.rollback()
        logger.error(f"Revocation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Certificate revocation failed"
        )

@app.post("/ocsp/check")
async def ocsp_check(request: OCSPRequest, db: Session = Depends(get_db)):
    try:
        cert = db.query(Certificate).filter(
            Certificate.serial_number == request.serial_number
        ).first()

        if not cert:
            return {"status": "UNKNOWN"}

        if cert.status == "REVOKED":
            return {
                "status": "REVOKED",
                "revocation_time": cert.revoked_at.isoformat(),
                "revocation_reason": cert.revocation_reason
            }

        return {"status": "GOOD"}

    except Exception as e:
        logger.error(f"OCSP check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OCSP check failed"
        )

@app.get("/crl")
async def get_crl(db: Session = Depends(get_db)):
    try:
        revoked_certs = db.query(CRLEntry).all()

        ca_key_crypto = crypto.PKey.from_cryptography_key(
            hsm_client.get_keypair(settings.CA_KEY_LABEL)[1]._private_key
        )
        crl_crypto = crypto.CRL()

        for cert in revoked_certs:
            revoked_cert = crypto.Revoked()
            revoked_cert.set_serial(cert.serial_number.encode())
            revoked_cert.set_reason(cert.reason.encode())
            revoked_cert.set_rev_date(datetime.now(UTC).strftime("%Y%m%d%H%M%SZ").encode())
            crl_crypto.add_revoked(revoked_cert)

        crl_crypto.set_issuer_name(ca_cert.subject)
        crl_crypto.sign(ca_key_crypto, 'sha256')

        crl_pem = crl_crypto.export(ca_cert, ca_key_crypto, crypto.FILETYPE_PEM).decode()

        return JSONResponse(
            content={"crl": crl_pem},
            media_type="application/x-pem-file"
        )

    except Exception as e:
        logger.error(f"CRL generation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="CRL generation failed"
        )

@app.get("/certificates/{serial_number}")
def get_certificate(serial_number: str, db: Session = Depends(get_db)):
    try:
        cert = db.query(Certificate).filter(
            Certificate.serial_number == serial_number
        ).first()

        if not cert:
            raise HTTPException(
                status_code=404,
                detail="Сертификат не найден"
            )

        return {
            "common_name": cert.common_name,
            "serial_number": cert.serial_number,
            "status": cert.status,
            "issued_at": cert.issued_at,
            "expires_at": cert.expires_at,
            "revoked_at": cert.revoked_at
        }
    finally:
        pass

@app.get("/audit")
def get_audit_logs(limit: int = 100, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()

    return [{
        "id": log.id,
        "action": log.action,
        "user": log.user,
        "target": log.target,
        "timestamp": log.created_at,
        "success": log.success
    } for log in logs]

@app.put("/certificates/revoke/{serial_number}")
def revoke_certificate(serial_number: str, db: Session = Depends(get_db)):
    try:
        cert = db.query(Certificate).filter(
            Certificate.serial_number == serial_number
        ).first()

        if not cert:
            raise HTTPException(
                status_code=404,
                detail="Сертификат не найден"
            )

        if cert.status == "REVOKED":
            return {"message": "Сертификат уже отозван"}

        cert.status = "REVOKED"
        cert.revoked_at = datetime.now(UTC)

        audit = AuditLog(
            action=f"Отозван сертификат SN: {serial_number}",
            target=f"SN: {serial_number}",
            success=True
        )

        db.add(cert)
        db.add(audit)
        db.commit()

        return {"message": "Сертификат успешно отозван"}
    except Exception as e:
        db.rollback()
        audit = AuditLog(
            action=f"Ошибка отзыва сертификата: {str(e)}",
            success=False,
            target=f"SN: {serial_number}"
        )
        db.add(audit)
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
