<?php
/**
 * 兼容入口：真正的控制器在 public/index.php。
 *
 * 旧部署可能把 web 根指向 api/omk 目录，这条入口保留可用性，并保证在线统计、
 * PIF 转发逻辑只有一份实现，避免两条路径行为不一致。
 */

declare(strict_types=1);

require __DIR__ . '/public/index.php';