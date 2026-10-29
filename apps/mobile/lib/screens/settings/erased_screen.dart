import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/icon.dart';

/// Shown after a remote wipe (M7): this device was revoked with "erase", so
/// the app layer crypto-shredded its keys and deleted the local store.
class ErasedScreen extends StatelessWidget {
  const ErasedScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final session = SecwetScope.of(context).session;
    return ColoredBox(
      color: p.bg,
      child: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: SecwetSpace.s6),
          child: Column(
            children: [
              Expanded(
                child: Center(
                  child: SingleChildScrollView(
                    child: EmptyState(
                      icon: SecwetIcons.trash,
                      title: 'This device was erased',
                      body: 'It was removed from the Secwet, so its keys and everything stored here were deleted. '
                          'Nothing can be recovered from this phone. Set Secwet up again to use it.',
                      action: SecwetButton(
                        label: 'Set up Secwet',
                        onPressed: () {
                          session.takeNotice();
                          session.acknowledgeErased();
                        },
                      ),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
