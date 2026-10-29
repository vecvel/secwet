import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/widgets.dart';

import '../../../app/secwet_scope.dart';
import '../../../app/shell.dart';
import '../../../core/secwet_api.dart';
import '../../../theme/secwet_theme.dart';
import '../../../theme/secwet_tokens.dart';
import '../../../widgets/controls.dart';
import '../../../widgets/icon.dart';
import '../../../widgets/layout.dart';
import '../../../widgets/overlays.dart';
import '../access.dart';
import '../common.dart';
import 'asset_preview.dart';

/// 50 MiB per asset, as the desktop.
const maxAssetSize = 50 * 1024 * 1024;

/// MIME type from a file name, for the few kinds the preview and other apps care about.
String mimeForName(String name) {
  final dot = name.lastIndexOf('.');
  final ext = dot < 0 ? '' : name.substring(dot + 1).toLowerCase();
  return switch (ext) {
    'png' => 'image/png',
    'jpg' || 'jpeg' => 'image/jpeg',
    'gif' => 'image/gif',
    'webp' => 'image/webp',
    'heic' => 'image/heic',
    'bmp' => 'image/bmp',
    'svg' => 'image/svg+xml',
    'pdf' => 'application/pdf',
    'txt' || 'log' => 'text/plain',
    'md' => 'text/markdown',
    'csv' => 'text/csv',
    'json' => 'application/json',
    'xml' => 'application/xml',
    'yml' || 'yaml' => 'application/yaml',
    'html' || 'htm' => 'text/html',
    'pem' || 'crt' || 'cer' => 'application/x-pem-file',
    'p12' || 'pfx' => 'application/x-pkcs12',
    'zip' => 'application/zip',
    _ => 'application/octet-stream',
  };
}

/// Hands [bytes] to the system save dialog without writing them as a plain
/// file in the app's temp folder (PlatformServices.saveBytes). Returns false
/// when the user cancelled.
Future<bool> saveAssetBytes(BuildContext context, String name, Uint8List bytes) async {
  final scope = SecwetScope.read(context);
  final safe = name.replaceAll(RegExp(r'[/\\:]'), '_');
  return scope.session.external(() => scope.api.platform.saveBytes(bytes, safe));
}

/// The Assets tab of an entry (desktop AssetManager): upload through the
/// system file picker, the asset list, preview, download, rename, delete.
class AssetsSection extends StatefulWidget {
  const AssetsSection({
    super.key,
    required this.item,
    required this.environmentId,
    required this.assets,
    required this.perms,
    required this.onChanged,
  });

  final Item item;
  final String? environmentId;
  final List<AssetMeta> assets;
  final Permissions perms;
  final VoidCallback onChanged;

  @override
  State<AssetsSection> createState() => _AssetsSectionState();
}

class _AssetsSectionState extends State<AssetsSection> {
  bool _uploading = false;
  String? _error;

  Future<void> _upload() async {
    final scope = SecwetScope.read(context);
    setState(() => _error = null);
    PickedFile? picked;
    try {
      picked = await scope.session.external(scope.api.platform.pickFile);
    } catch (e) {
      if (mounted) setState(() => _error = errorText(e, 'Failed to open the file picker.'));
      return;
    }
    if (picked == null) return;
    final file = File(picked.path);
    try {
      final size = await file.length();
      if (size > maxAssetSize) {
        if (mounted) setState(() => _error = '"${picked!.name}" exceeds 50 MiB limit.');
        return;
      }
      if (mounted) setState(() => _uploading = true);
      final bytes = await file.readAsBytes();
      await scope.api.uploadAsset(widget.item.id, picked.name, bytes,
          environmentId: widget.environmentId, mime: mimeForName(picked.name));
      bytes.fillRange(0, bytes.length, 0);
      widget.onChanged();
    } catch (e) {
      if (mounted) setState(() => _error = errorText(e, 'Failed to upload asset.'));
    } finally {
      if (await file.exists()) await file.delete();
      if (mounted) setState(() => _uploading = false);
    }
  }

  Future<void> _download(AssetMeta asset) async {
    try {
      final res = await SecwetScope.read(context).api.downloadAsset(asset.id);
      if (!mounted) return;
      await saveAssetBytes(context, asset.name, res.bytes);
      res.bytes.fillRange(0, res.bytes.length, 0);
    } catch (e) {
      if (mounted) setState(() => _error = errorText(e, 'Failed to download asset.'));
    }
  }

  Future<void> _rename(AssetMeta asset) async {
    final api = SecwetScope.read(context).api;
    final renamed = await showNameDialog(
      context,
      title: 'Rename asset',
      label: 'Asset name',
      initial: asset.name,
      confirmLabel: 'Rename',
      validate: (v) {
        final t = v.trim();
        if (t.isEmpty) return 'Asset name cannot be empty.';
        if (widget.assets.any((a) => a.id != asset.id && a.name.toLowerCase() == t.toLowerCase())) {
          return 'An asset called "$t" already exists here.';
        }
        return null;
      },
      onSubmit: (name) => api.renameAsset(asset.id, name),
    );
    if (renamed != null) widget.onChanged();
  }

  Future<void> _delete(AssetMeta asset) async {
    final ok = await showConfirmDialog(
      context,
      title: 'Delete "${asset.name}"?',
      message: 'Are you sure you want to permanently delete this asset?',
      confirmLabel: 'Delete asset',
    );
    if (!ok || !mounted) return;
    try {
      await SecwetScope.read(context).api.deleteAsset(asset.id);
      widget.onChanged();
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't delete this asset.");
    }
  }

  void _preview(AssetMeta asset) => pushScreen(context, AssetPreviewScreen(asset: asset, itemName: widget.item.name));

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final perms = widget.perms;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (perms.canWrite) ...[
          Tappable(
            label: 'Upload asset',
            onTap: _uploading ? null : _upload,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: SecwetSpace.s4, vertical: SecwetSpace.s5),
              decoration: BoxDecoration(
                color: p.surface,
                border: Border.all(color: p.borderStrong),
                borderRadius: BorderRadius.circular(SecwetRadius.card),
              ),
              child: Column(
                children: [
                  SecwetIcon(SecwetIcons.plus, size: 24, color: p.textTertiary),
                  const SizedBox(height: SecwetSpace.s2),
                  Text(
                    _uploading ? 'Uploading encrypted asset...' : 'Tap to upload an asset',
                    style: SecwetText.md(p, weight: FontWeight.w500),
                  ),
                  const SizedBox(height: SecwetSpace.s1),
                  Text(
                    'Encrypted on-device before storage · Up to 50 MiB per asset',
                    textAlign: TextAlign.center,
                    style: SecwetText.sm(p),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: SecwetSpace.s3),
        ],
        if (_error != null) ...[
          Text(_error!, style: SecwetText.sm(p, color: p.danger)),
          const SizedBox(height: SecwetSpace.s3),
        ],
        if (widget.assets.isEmpty)
          EmptyState(
            icon: SecwetIcons.folder,
            title: 'No assets yet',
            body: 'Upload documents, certificates, PDFs, images, or configurations.',
            action: perms.canWrite
                ? SecwetButton(label: 'Upload asset', icon: SecwetIcons.plus, variant: ButtonVariant.secondary, onPressed: _upload)
                : null,
          )
        else
          SecwetCard(
            children: [
              for (final a in widget.assets)
                ListRow(
                  title: a.name,
                  alignTop: true,
                  leading: const IconTile(icon: SecwetIcons.folder),
                  meta: '${formatBytes(a.sizeBytes)} · Uploaded ${formatAgo(a.updatedAt)}',
                  below: PillRow(children: [SecwetBadge(a.mimeType.isEmpty ? 'application/octet-stream' : a.mimeType)]),
                  onTap: () => _preview(a),
                  trailing: SecwetMenuButton(
                    label: 'Actions for ${a.name}',
                    entries: [
                      MenuEntry('Preview', icon: SecwetIcons.eye, onSelected: () => _preview(a)),
                      MenuEntry('Download', icon: SecwetIcons.download, onSelected: () => _download(a)),
                      if (perms.canWrite) MenuEntry('Rename', icon: SecwetIcons.pencil, onSelected: () => _rename(a)),
                      if (perms.canDelete) MenuEntry('Delete', icon: SecwetIcons.trash, danger: true, onSelected: () => _delete(a)),
                    ],
                  ),
                ),
            ],
          ),
      ],
    );
  }
}
