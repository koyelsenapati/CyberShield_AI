import axios from "axios";
import { api } from "./api";
import type {
  FileIntegrityResponse,
} from "../types/fileIntegrity";

/**
 * Hash a file inside the signed-in user's monitored directory on the server.
 * `filePath` is relative to that directory. Uses the shared axios client, so
 * the Authorization header and 401 -> logout handling come from api.ts.
 */
export async function scanFileIntegrity(
  filePath: string,
): Promise<FileIntegrityResponse> {
  try {
    const response = await api.post<FileIntegrityResponse>(
      "/file-integrity/",
      null,
      { params: { file_path: filePath } },
    );

    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const detail = error.response?.data?.detail;

      throw new Error(
        typeof detail === "string"
          ? detail
          : "File integrity scan failed.",
      );
    }

    throw error;
  }
}
