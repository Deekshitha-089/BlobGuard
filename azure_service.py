
import os

from azure.storage.blob import BlobServiceClient, ContentSettings
from azure.core.exceptions import ResourceNotFoundError
from werkzeug.utils import secure_filename


class AzureConfigurationError(RuntimeError):
    pass


class AzureBlobService:

    def __init__(self):
        cs = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

        self.container_name = os.getenv(
            "AZURE_CONTAINER_NAME",
            "blobguard-files"
        )

        if not cs:
            raise AzureConfigurationError(
                "Missing AZURE_STORAGE_CONNECTION_STRING in your .env file."
            )

        self.client = BlobServiceClient.from_connection_string(cs)

        self.container = self.client.get_container_client(
            self.container_name
        )

    # --------------------------------------------------
    # HELPER: GENERATE USER-SPECIFIC BLOB NAME
    # --------------------------------------------------

    @staticmethod
    def _name(user_id, filename):
        filename = secure_filename(filename or "")

        if not filename or "/" in filename or "\\" in filename:
            raise ValueError("Invalid filename.")

        return f"users/{user_id}/{filename}"

    # --------------------------------------------------
    # HELPER: FORMAT FILE SIZE
    # --------------------------------------------------

    @staticmethod
    def format_bytes(size):
        size = float(size)

        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024 or unit == "TB":
                if unit == "B":
                    return f"{int(size)} B"

                return f"{size:.1f} {unit}"

            size /= 1024

    # --------------------------------------------------
    # UPLOAD FILE
    # --------------------------------------------------

    def upload_file(
        self,
        user_id,
        filename,
        stream,
        content_type
    ):
        blob_name = self._name(user_id, filename)

        blob = self.container.get_blob_client(blob_name)

        blob.upload_blob(
            stream,
            overwrite=True,
            content_settings=ContentSettings(
                content_type=content_type
            )
        )

        return {
            "name": filename,
            "blob_name": blob_name,
            "message": "File uploaded successfully."
        }

    # --------------------------------------------------
    # LIST CURRENT USER FILES
    # --------------------------------------------------

    def list_user_files(self, user_id):

        prefix = f"users/{user_id}/"

        found = {}

        # Ask Azure for blobs and their retained versions.
        for item in self.container.list_blobs(
            name_starts_with=prefix,
            include=["versions"]
        ):

            # IMPORTANT:
            # Only display the current version in My Files.
            # Historical versions alone should not make a
            # deleted file appear as an active file.

            if not getattr(item, "is_current_version", False):
                continue

            blob_name = item.name

            # Avoid duplicate entries.
            if blob_name not in found:

                found[blob_name] = {
                    "name": blob_name[len(prefix):],
                    "blob_name": blob_name,
                    "size": item.size or 0,
                    "last_modified": (
                        item.last_modified.isoformat()
                        if item.last_modified
                        else ""
                    ),
                    "versions": []
                }

            version_id = getattr(item, "version_id", None)

            if version_id:
                found[blob_name]["versions"].append({
                    "version_id": version_id,
                    "is_current": True,
                    "last_modified": (
                        item.last_modified.isoformat()
                        if item.last_modified
                        else ""
                    ),
                    "size": item.size or 0
                })

        # Collect the previous versions for each active file.
        for blob_name, file_data in found.items():

            for item in self.container.list_blobs(
                name_starts_with=blob_name,
                include=["versions"]
            ):

                if item.name != blob_name:
                    continue

                version_id = getattr(item, "version_id", None)

                if not version_id:
                    continue

                # Avoid adding the current version twice.
                if any(
                    v["version_id"] == version_id
                    for v in file_data["versions"]
                ):
                    continue

                file_data["versions"].append({
                    "version_id": version_id,
                    "is_current": bool(
                        getattr(item, "is_current_version", False)
                    ),
                    "last_modified": (
                        item.last_modified.isoformat()
                        if item.last_modified
                        else ""
                    ),
                    "size": item.size or 0
                })

            file_data["versions"].sort(
                key=lambda v: v["last_modified"],
                reverse=True
            )

            file_data["version_count"] = len(
                file_data["versions"]
            )

        return sorted(
            found.values(),
            key=lambda x: x["name"].lower()
        )

    # --------------------------------------------------
    # LIST VERSIONS OF A FILE
    # --------------------------------------------------

    def list_versions(self, user_id, filename):

        blob_name = self._name(user_id, filename)

        versions = []

        for item in self.container.list_blobs(
            name_starts_with=blob_name,
            include=["versions"]
        ):

            if item.name != blob_name:
                continue

            version_id = getattr(item, "version_id", None)

            if not version_id:
                continue

            versions.append({
                "version_id": version_id,
                "is_current": bool(
                    getattr(item, "is_current_version", False)
                ),
                "last_modified": (
                    item.last_modified.isoformat()
                    if item.last_modified
                    else ""
                ),
                "size": item.size or 0
            })

        versions.sort(
            key=lambda v: v["last_modified"],
            reverse=True
        )

        if not versions:
            raise ValueError(
                "No retained versions found for this file."
            )

        return versions

    # --------------------------------------------------
    # VERIFY VERSION BELONGS TO THE USER'S FILE
    # --------------------------------------------------

    def _verify_version(
        self,
        user_id,
        filename,
        version_id
    ):

        blob_name = self._name(user_id, filename)

        if not version_id:
            raise ValueError("A version ID is required.")

        versions = self.list_versions(
            user_id,
            filename
        )

        if not any(
            v["version_id"] == version_id
            for v in versions
        ):
            raise ValueError(
                "That version is not available for this file."
            )

        return blob_name

    # --------------------------------------------------
    # RESTORE A PREVIOUS VERSION
    # --------------------------------------------------

    def restore_version(
        self,
        user_id,
        filename,
        version_id
    ):

        blob_name = self._verify_version(
            user_id,
            filename,
            version_id
        )

        source = self.container.get_blob_client(
            blob_name,
            version_id=version_id
        )

        # Read the selected historical version.
        data = source.download_blob().readall()

        # Preserve its content type.
        props = source.get_blob_properties()

        content_type = (
            getattr(
                props.content_settings,
                "content_type",
                None
            )
            or "application/octet-stream"
        )

        # Upload the selected content as the new current version.
        current_blob = self.container.get_blob_client(
            blob_name
        )

        current_blob.upload_blob(
            data,
            overwrite=True,
            content_settings=ContentSettings(
                content_type=content_type
            )
        )

        return True

    # --------------------------------------------------
    # DOWNLOAD CURRENT FILE
    # --------------------------------------------------

    def download_file(self, user_id, filename):

        blob_name = self._name(user_id, filename)

        blob = self.container.get_blob_client(
            blob_name
        )

        props = blob.get_blob_properties()

        content_type = (
            getattr(
                props.content_settings,
                "content_type",
                None
            )
            or "application/octet-stream"
        )

        data = blob.download_blob().readall()

        return data, content_type, filename

    # --------------------------------------------------
    # DELETE CURRENT FILE
    # --------------------------------------------------

    def delete_file(self, user_id, filename):

        blob_name = self._name(user_id, filename)

        try:
            blob = self.container.get_blob_client(
                blob_name
            )

            blob.delete_blob()

        except ResourceNotFoundError:
            raise ValueError("File not found.")

        return True