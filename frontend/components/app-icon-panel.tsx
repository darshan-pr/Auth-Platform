"use client";

import { useEffect, useMemo, useState, type ChangeEvent, type FormEvent } from "react";
import type { ConsoleApp } from "../lib/types";
import { consoleApi } from "../lib/api";
import { Button, Card, ErrorBanner, Field } from "./ui";

type IconMode = "upload" | "url";

const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_DATA_URL_LENGTH = 500_000;

export function AppIconPanel({
  app,
  onUpdated
}: {
  app: ConsoleApp;
  onUpdated: (app: ConsoleApp) => void;
}) {
  const [mode, setMode] = useState<IconMode>(app.iconDataUrl ? "upload" : "url");
  const [url, setUrl] = useState(app.iconUrl ?? "");
  const [file, setFile] = useState<File | null>(null);
  const [filePreview, setFilePreview] = useState("");
  const [positionX, setPositionX] = useState(app.iconPositionX);
  const [positionY, setPositionY] = useState(app.iconPositionY);
  const [zoom, setZoom] = useState(app.iconZoomPercent);
  const [previewFailed, setPreviewFailed] = useState(false);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!file) {
      setFilePreview("");
      return;
    }
    const objectUrl = URL.createObjectURL(file);
    setFilePreview(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [file]);

  useEffect(() => {
    setMode(app.iconDataUrl ? "upload" : "url");
    setUrl(app.iconUrl ?? "");
    setFile(null);
    setPositionX(app.iconPositionX);
    setPositionY(app.iconPositionY);
    setZoom(app.iconZoomPercent);
  }, [app.id, app.iconDataUrl, app.iconUrl, app.iconPositionX, app.iconPositionY, app.iconZoomPercent]);

  const previewSrc = useMemo(() => {
    if (mode === "upload") return filePreview || app.iconDataUrl || "";
    return url.trim();
  }, [app.iconDataUrl, filePreview, mode, url]);
  const isDirty =
    Boolean(file) ||
    url !== (app.iconUrl ?? "") ||
    positionX !== app.iconPositionX ||
    positionY !== app.iconPositionY ||
    zoom !== app.iconZoomPercent;

  const chooseFile = (event: ChangeEvent<HTMLInputElement>) => {
    const selected = event.target.files?.[0] ?? null;
    setError("");
    setPreviewFailed(false);
    if (!selected) {
      setFile(null);
      return;
    }
    if (!["image/png", "image/jpeg", "image/webp"].includes(selected.type)) {
      setError("Choose a PNG, JPEG, or WebP image.");
      setFile(null);
      event.target.value = "";
      return;
    }
    if (selected.size > MAX_FILE_BYTES) {
      setError("Choose an image smaller than 5 MB.");
      setFile(null);
      event.target.value = "";
      return;
    }
    setFile(selected);
  };

  const save = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      let payload: Record<string, unknown>;
      if (mode === "url") {
        const normalizedUrl = url.trim();
        if (!normalizedUrl) throw new Error("Enter an HTTPS image URL.");
        if (!/^https:\/\//i.test(normalizedUrl) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/i.test(normalizedUrl)) {
          throw new Error("Use an HTTPS image URL.");
        }
        payload = {
          iconUrl: normalizedUrl,
          iconDataUrl: "",
          iconPositionX: positionX,
          iconPositionY: positionY,
          iconZoomPercent: zoom
        };
      } else {
        const source = filePreview || app.iconDataUrl;
        if (!source) throw new Error("Choose an image to upload.");
        const iconDataUrl = await cropImage(source, positionX, positionY, zoom);
        if (iconDataUrl.length > MAX_DATA_URL_LENGTH) {
          throw new Error("The cropped image is too large. Choose a simpler image.");
        }
        payload = {
          iconUrl: "",
          iconDataUrl,
          iconPositionX: 50,
          iconPositionY: 50,
          iconZoomPercent: 100
        };
      }
      onUpdated(await consoleApi.updateApp(app.id, payload));
      setFile(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to save the application icon.");
    } finally {
      setSaving(false);
    }
  };

  const remove = async () => {
    setSaving(true);
    setError("");
    try {
      onUpdated(await consoleApi.updateApp(app.id, {
        iconUrl: "",
        iconDataUrl: "",
        iconPositionX: 50,
        iconPositionY: 50,
        iconZoomPercent: 100
      }));
      setFile(null);
      setPreviewFailed(false);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to remove the application icon.");
    } finally {
      setSaving(false);
    }
  };

  const currentIcon = Boolean(app.iconUrl || app.iconDataUrl);

  return (
    <Card className="app-icon-card">
      <div className="card-heading">
        <div>
          <h2>Application icon</h2>
          <p>Upload an image or use an HTTPS URL. Preview and adjust the crop before saving.</p>
        </div>
        {currentIcon && <Button disabled={saving} onClick={remove} type="button" variant="quiet">Remove icon</Button>}
      </div>
      {error && <ErrorBanner message={error} />}
      <form onSubmit={save}>
        <div className="app-icon-editor">
          <div className="app-icon-preview-column">
            <div className="app-icon-preview-frame">
              {previewSrc && !previewFailed
                ? <img
                    alt="Application icon preview"
                    onError={() => setPreviewFailed(true)}
                    onLoad={() => setPreviewFailed(false)}
                    src={previewSrc}
                    style={{
                      objectPosition: `${positionX}% ${positionY}%`,
                      transform: `scale(${zoom / 100})`,
                      transformOrigin: `${positionX}% ${positionY}%`
                    }}
                  />
                : <span>{previewFailed ? "Preview unavailable" : "Icon preview"}</span>}
            </div>
            <span className="app-icon-preview-label">Preview</span>
          </div>
          <div className="app-icon-fields">
            <div className="app-icon-mode" aria-label="Icon source">
              <button aria-pressed={mode === "upload"} onClick={() => { setMode("upload"); setPreviewFailed(false); }} type="button">Upload image</button>
              <button aria-pressed={mode === "url"} onClick={() => { setMode("url"); setPreviewFailed(false); }} type="button">Use image URL</button>
            </div>
            {mode === "upload"
              ? <label className="field">
                  <span className="field-label">Upload icon</span>
                  <input accept="image/png,image/jpeg,image/webp" onChange={chooseFile} type="file" />
                  <span className="field-hint">PNG, JPEG, or WebP, up to 5 MB. The saved image is cropped and optimized.</span>
                </label>
              : <Field
                hint="Use a publicly reachable HTTPS image URL."
                  label="Image URL"
                  onChange={(event) => { setUrl(event.target.value); setPreviewFailed(false); }}
                  placeholder="https://example.com/app-icon.png"
                  type="url"
                  value={url}
                />}
            <div className="app-icon-adjustments">
              <label>
                <span>Zoom <output>{zoom}%</output></span>
                <input max={300} min={100} onChange={(event) => setZoom(Number(event.target.value))} type="range" value={zoom} />
              </label>
              <label>
                <span>Horizontal position <output>{positionX}%</output></span>
                <input max={100} min={0} onChange={(event) => setPositionX(Number(event.target.value))} type="range" value={positionX} />
              </label>
              <label>
                <span>Vertical position <output>{positionY}%</output></span>
                <input max={100} min={0} onChange={(event) => setPositionY(Number(event.target.value))} type="range" value={positionY} />
              </label>
            </div>
            <div className="app-icon-actions">
              <Button disabled={saving || !isDirty} type="submit">{saving ? "Saving…" : "Save icon"}</Button>
            </div>
          </div>
        </div>
      </form>
    </Card>
  );
}

function cropImage(source: string, positionX: number, positionY: number, zoom: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => {
      const baseSize = Math.min(image.naturalWidth, image.naturalHeight);
      const cropSize = baseSize * (100 / zoom);
      const availableX = image.naturalWidth - cropSize;
      const availableY = image.naturalHeight - cropSize;
      const left = availableX * (positionX / 100);
      const top = availableY * (positionY / 100);
      const canvas = document.createElement("canvas");
      canvas.width = 256;
      canvas.height = 256;
      const context = canvas.getContext("2d");
      if (!context) {
        reject(new Error("Your browser could not prepare the icon image."));
        return;
      }
      context.drawImage(image, left, top, cropSize, cropSize, 0, 0, canvas.width, canvas.height);
      let result = canvas.toDataURL("image/webp", 0.88);
      if (result.length > MAX_DATA_URL_LENGTH) {
        canvas.width = 128;
        canvas.height = 128;
        context.drawImage(image, left, top, cropSize, cropSize, 0, 0, canvas.width, canvas.height);
        result = canvas.toDataURL("image/webp", 0.78);
      }
      resolve(result);
    };
    image.onerror = () => reject(new Error("The selected image could not be loaded."));
    image.src = source;
  });
}
