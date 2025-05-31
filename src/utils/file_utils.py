"""aa"""
import uuid
from pathlib import Path
import aiofiles
from fastapi import HTTPException, UploadFile, status

from config.settings import Settings as settings


def validate_image_file(file: UploadFile) -> None:
    """Validate uploaded image file."""
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No filename provided"
        )
    
    # Check file extension
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type not allowed. Supported formats: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        )
    
    # Check file size (this is an approximation, actual size check happens during upload)
    if hasattr(file, 'size') and file.size and file.size > settings.MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size: {settings.MAX_FILE_SIZE // (1024*1024)}MB"
        )

def generate_unique_filename(original_filename: str, user_id: int) -> str:
    """Generate a unique filename for the uploaded image."""
    file_ext = Path(original_filename).suffix.lower()
    unique_id = str(uuid.uuid4())
    return f"user_{user_id}_{unique_id}{file_ext}"

async def save_uploaded_file(file: UploadFile, filepath: Path) -> None:
    """Save uploaded file to disk with size validation."""
    total_size = 0
    async with aiofiles.open(filepath, 'wb') as f:
        while chunk := await file.read(8192):  # Read in 8KB chunks
            total_size += len(chunk)
            if total_size > settings.MAX_FILE_SIZE:
                # Remove partially written file
                filepath.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File too large. Maximum size: {settings.MAX_FILE_SIZE // (1024*1024)}MB"
                )
            await f.write(chunk)

def delete_profile_picture_file(profile_picture_url: str) -> None:
    """Delete profile picture file from disk."""
    if profile_picture_url:
        # Extract filename from URL (assuming URL format: /media/profile_pictures/filename)
        filename = Path(profile_picture_url).name
        file_path = settings.MEDIA_DIR / filename
        file_path.unlink(missing_ok=True)