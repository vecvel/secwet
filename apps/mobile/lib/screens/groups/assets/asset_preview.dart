import 'dart:convert';
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
import '../common.dart';
import 'assets_section.dart';

/// Full-screen preview of an asset (desktop AssetPreviewDialog): images,
/// text and Markdown, PDF pages drawn by the platform, otherwise the type and
/// checksum. The decrypted bytes stay in memory only while the screen is open.
class AssetPreviewScreen extends StatefulWidget {
  const AssetPreviewScreen({super.key, required this.asset, required this.itemName});

  final AssetMeta asset;
  final String itemName;

  @override
  State<AssetPreviewScreen> createState() => _AssetPreviewScreenState();
}

class _AssetPreviewScreenState extends State<AssetPreviewScreen> {
  Uint8List? _bytes;
  List<Uint8List>? _pdfPages;
  String? _error;
  bool _loading = true;

  AssetMeta get _asset => widget.asset;
  String get _name => _asset.name.toLowerCase();
  String get _mime => _asset.mimeType.isEmpty ? mimeForName(_asset.name) : _asset.mimeType;

  bool get _isImage => _mime.startsWith('image/') && !_mime.contains('svg') && !_mime.contains('heic');
  bool get _isPdf => _mime == 'application/pdf' || _name.endsWith('.pdf');
  bool get _isMarkdown => _name.endsWith('.md') || _mime == 'text/markdown';
  bool get _isText =>
      _mime.startsWith('text/') ||
      _mime == 'application/json' ||
      _name.endsWith('.json') ||
      _name.endsWith('.csv') ||
      _name.endsWith('.env') ||
      _name.endsWith('.txt');

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  Future<void> _load() async {
    final api = SecwetScope.read(context).api;
    try {
      final res = await api.downloadAsset(_asset.id);
      List<Uint8List>? pages;
      if (_isPdf) pages = await api.platform.renderPdf(res.bytes, width: 1200);
      if (!mounted) return;
      setState(() {
        _bytes = res.bytes;
        _pdfPages = pages;
        _loading = false;
      });
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = errorText(e, 'Failed to download asset for preview.');
          _loading = false;
        });
      }
    }
  }

  @override
  void dispose() {
    _bytes?.fillRange(0, _bytes!.length, 0);
    _bytes = null;
    _pdfPages = null;
    super.dispose();
  }

  Future<void> _download() async {
    final bytes = _bytes;
    if (bytes == null) return;
    try {
      await saveAssetBytes(context, _asset.name, bytes);
    } catch (e) {
      if (mounted) showError(context, e, 'Failed to download asset.');
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return ShellPage(
      topBar: TopBar(
        title: _asset.name,
        actions: [
          SecwetButton(label: 'Download', icon: SecwetIcons.download, onPressed: _bytes == null ? null : _download),
        ],
      ),
      children: [
        Text('${formatBytes(_asset.sizeBytes)} · Uploaded ${formatAgo(_asset.updatedAt)}', style: SecwetText.sm(p)),
        const SizedBox(height: SecwetSpace.s3),
        if (_loading) Text('Loading preview...', style: SecwetText.md(p, color: p.textSecondary)),
        if (_error != null) Text(_error!, style: SecwetText.md(p, color: p.danger)),
        if (!_loading && _error == null && _bytes != null) _content(p, _bytes!),
      ],
    );
  }

  Widget _content(SecwetPalette p, Uint8List bytes) {
    Widget framed(Widget child, {EdgeInsets padding = EdgeInsets.zero}) => Container(
          padding: padding,
          decoration: BoxDecoration(
            color: p.surface,
            border: Border.all(color: p.border),
            borderRadius: BorderRadius.circular(SecwetRadius.card),
          ),
          clipBehavior: Clip.antiAlias,
          child: child,
        );

    if (_isImage) {
      return framed(InteractiveViewer(
        maxScale: 6,
        child: Image.memory(bytes, fit: BoxFit.contain, gaplessPlayback: true, errorBuilder: (_, _, _) => _unsupported(p)),
      ));
    }
    if (_isPdf) {
      final pages = _pdfPages ?? const [];
      if (pages.isEmpty) return _unsupported(p);
      return Column(
        children: [
          for (final page in pages)
            Padding(
              padding: const EdgeInsets.only(bottom: SecwetSpace.s3),
              child: framed(Image.memory(page, fit: BoxFit.fitWidth)),
            ),
        ],
      );
    }
    if (_isMarkdown || _isText) {
      final text = utf8.decode(bytes, allowMalformed: true);
      return framed(
        _isMarkdown ? _MarkdownPreview(text) : Text(text, style: SecwetText.md(p)),
        padding: const EdgeInsets.all(14),
      );
    }
    return _unsupported(p);
  }

  Widget _unsupported(SecwetPalette p) {
    final sha = _asset.sha256.length > 16 ? '${_asset.sha256.substring(0, 16)}...' : _asset.sha256;
    return EmptyState(
      icon: SecwetIcons.folder,
      title: 'Preview is not available for this asset format.',
      body: 'MIME: $_mime · SHA-256: $sha',
    );
  }
}

/// The desktop's minimal Markdown preview: headings, list lines, paragraphs.
class _MarkdownPreview extends StatelessWidget {
  const _MarkdownPreview(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final children = <Widget>[];
    for (final line in text.split('\n')) {
      if (line.startsWith('# ')) {
        children.add(Text(line.substring(2), style: SecwetText.body(p).copyWith(fontSize: 22, fontWeight: FontWeight.w600)));
      } else if (line.startsWith('## ')) {
        children.add(Text(line.substring(3), style: SecwetText.body(p).copyWith(fontSize: 18, fontWeight: FontWeight.w600)));
      } else if (line.startsWith('### ')) {
        children.add(Text(line.substring(4), style: SecwetText.body(p).copyWith(fontSize: 16, fontWeight: FontWeight.w600)));
      } else if (line.startsWith('- ') || line.startsWith('* ')) {
        children.add(Text('•  ${line.substring(2)}', style: SecwetText.body(p)));
      } else if (line.trim().isEmpty) {
        children.add(const SizedBox(height: SecwetSpace.s2));
      } else {
        children.add(Text(line, style: SecwetText.body(p)));
      }
    }
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: children);
  }
}
