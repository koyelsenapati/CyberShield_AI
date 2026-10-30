import { useState } from "react";
import {
  CheckCircle2,
  FileCheck2,
  Loader2,
  ShieldAlert,
} from "lucide-react";

import DashboardLayout from "../../layouts/DashboardLayout";
import PageHeader from "../../components/common/PageHeader";

import { scanFileIntegrity } from "../../services/fileIntegrity";
import type {
  FileIntegrityScan,
} from "../../types/fileIntegrity";

export default function FileIntegrity() {
  const [filePath, setFilePath] = useState("");
  const [scan, setScan] =
    useState<FileIntegrityScan | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleScan() {
    if (!filePath.trim()) {
      setError("Enter a valid file path.");
      return;
    }

    try {
      setLoading(true);
      setError("");
      setScan(null);

      const response =
        await scanFileIntegrity(filePath.trim());

      setScan(response.scan);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to scan the file.",
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <DashboardLayout>
      <div className="mx-auto max-w-[1600px] space-y-6">
        <PageHeader
          eyebrow="FILE SECURITY"
          title="File Integrity"
          description="Hash files in your monitored server directory and compare each scan with the previous one."
        />

        <div className="rounded-xl border border-white/10 bg-[#1F2937]/60 p-6">
          <div className="flex items-center gap-3">
            <FileCheck2 className="h-5 w-5 text-[#00F0FF]" />

            <div>
              <h2 className="text-sm font-semibold text-white">
                SHA-256 Integrity Scanner
              </h2>

              <p className="mt-1 text-[10px] text-gray-600">
                Paths are relative to your monitored directory on the server.
              </p>
            </div>
          </div>

          <div className="mt-6 flex flex-col gap-3 lg:flex-row">
            <input
              value={filePath}
              onChange={(event) =>
                setFilePath(event.target.value)
              }
              placeholder="Enter file path (relative to your monitored directory)"
              className="flex-1 rounded-lg border border-white/10 bg-[#0B0F17] px-4 py-3 font-mono text-xs text-white outline-none placeholder:text-gray-700 focus:border-[#00F0FF]/40"
              disabled={loading}
            />

            <button
              type="button"
              onClick={handleScan}
              disabled={loading}
              className="flex items-center justify-center gap-2 rounded-lg border border-[#00F0FF]/30 bg-[#00F0FF]/5 px-6 py-3 text-xs font-semibold text-[#00F0FF] transition hover:bg-[#00F0FF]/10 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading && (
                <Loader2 className="h-4 w-4 animate-spin" />
              )}

              {loading ? "Scanning..." : "Calculate SHA-256"}
            </button>
          </div>

          {error && (
            <div className="mt-4 flex items-start gap-3 rounded-lg border border-[#EF4444]/20 bg-[#EF4444]/5 p-4">
              <ShieldAlert className="mt-0.5 h-4 w-4 text-[#EF4444]" />

              <p className="text-xs text-[#EF4444]">
                {error}
              </p>
            </div>
          )}
        </div>

        {scan && (
          <div className="rounded-xl border border-white/10 bg-[#1F2937]/60 p-6">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-[10px] uppercase tracking-widest text-gray-600">
                  Scan Result
                </p>

                <h2 className="mt-1 text-sm font-semibold text-white">
                  File Integrity Result
                </h2>
              </div>

              <div
                className={
                  scan.status === "Modified"
                    ? "flex items-center gap-2 rounded-lg border border-[#EF4444]/20 bg-[#EF4444]/5 px-3 py-2"
                    : "flex items-center gap-2 rounded-lg border border-[#10B981]/20 bg-[#10B981]/5 px-3 py-2"
                }
              >
                {scan.status === "Modified" ? (
                  <ShieldAlert className="h-4 w-4 text-[#EF4444]" />
                ) : (
                  <CheckCircle2 className="h-4 w-4 text-[#10B981]" />
                )}

                <span
                  className={
                    scan.status === "Modified"
                      ? "text-[10px] font-semibold text-[#EF4444]"
                      : "text-[10px] font-semibold text-[#10B981]"
                  }
                >
                  {scan.status}
                </span>
              </div>
            </div>

            <div className="mt-6 space-y-4">
              <div>
                <p className="text-[9px] uppercase tracking-wider text-gray-600">
                  File
                </p>

                <p className="mt-1 break-all font-mono text-xs text-gray-300">
                  {scan.file_path}
                </p>
              </div>

              <div>
                <p className="text-[9px] uppercase tracking-wider text-gray-600">
                  Algorithm
                </p>

                <p className="mt-1 font-mono text-xs text-[#00F0FF]">
                  {scan.algorithm}
                </p>
              </div>

              <div>
                <p className="text-[9px] uppercase tracking-wider text-gray-600">
                  SHA-256
                </p>

                <div className="mt-2 break-all rounded-lg bg-[#0B0F17] p-4 font-mono text-xs leading-6 text-gray-300">
                  {scan.file_hash}
                </div>
              </div>

              {scan.created_at && (
                <div>
                  <p className="text-[9px] uppercase tracking-wider text-gray-600">
                    Created
                  </p>

                  <p className="mt-1 text-xs text-gray-400">
                    {scan.created_at}
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {!loading && !scan && !error && (
          <div className="rounded-xl border border-white/10 bg-[#1F2937]/40 px-6 py-12 text-center">
            <FileCheck2 className="mx-auto h-8 w-8 text-gray-700" />

            <p className="mt-3 text-xs text-gray-600">
              Enter a file path to start an integrity scan.
            </p>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
