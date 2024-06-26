<?php
/**
 * DokuWiki Starter Bootstrap Template
 *
 * @link     http://dokuwiki.org/template:starterbootstrap
 * @author   Cameron Littel <cameron@camlittle.com>
 */

if (!defined('DOKU_INC')) die(); /* must be run from within DokuWiki */
@require_once(dirname(__FILE__).'/tpl_functions.php'); /* include hook for template functions */

$showTools = !tpl_getConf('hideTools') || ( tpl_getConf('hideTools') && $_SERVER['REMOTE_USER'] );
$showSidebar = page_findnearest($conf['sidebar']) && ($ACT=='show');
$sidebarCols = (int) tpl_getConf('sidebar_cols');
$sidebarPos = tpl_getConf('sidebar_pos');
if ($sidebarCols < 0 || $sidebarCols >= 12) {
	$sidebarCols = 3;
}

?><!DOCTYPE html>
<html xml:lang="<?php echo $conf['lang'] ?>" lang="<?php echo $conf['lang'] ?>" dir="<?php echo $lang['direction'] ?>" class="no-js">
<head>
    <meta charset="UTF-8" />
    <!--[if IE]><meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" /><![endif]-->
    <title>
        <?php tpl_pagetitle() ?>
        [<?php echo strip_tags($conf['title'])?>]
    </title>
    <?php @require_once(dirname(__FILE__).'/head-css.php'); ?>
</head>

<body data-spy="scroll" data-target="#dw_toc">
    <?php /* with these Conditional Comments you can better address IE issues in CSS files,
             precede CSS rules by #IE6 for IE6, #IE7 for IE7 and #IE8 for IE8 (div closes at the bottom) */ ?>
    <!--[if IE 6 ]><div id="IE6"><![endif]--><!--[if IE 7 ]><div id="IE7"><![endif]--><!--[if IE 8 ]><div id="IE8"><![endif]-->

    <?php /* the "dokuwiki__top" id is needed somewhere at the top, because that's where the "back to top" button/link links to */ ?>
    <?php /* classes mode_<action> are added to make it possible to e.g. style a page differently if it's in edit mode,
         see http://www.dokuwiki.org/devel:action_modes for a list of action modes */ ?>
    <?php /* .dokuwiki should always be in one of the surrounding elements (e.g. plugins and templates depend on it) */ ?>
    <div id="dokuwiki__site" ><div id="dokuwiki__top"
        class="dokuwiki site mode_<?php echo $ACT ?> <?php echo ($showSidebar) ? 'hasSidebar' : '' ?>">
        <div class="navbar navbar-default navbar-fixed-top">
            <?php tpl_includeFile('header.html') ?>
            <div class="navbar-header">
                <button class="navbar-toggle" data-toggle="collapse" data-target="#topnav" type="button">
                    <span class="sr-only">Toggle Navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <?php tpl_link(wl(),$conf['title'],'accesskey="h" title="[H]" class="navbar-brand"') ?>
            </div>
            <div class="navbar-collapse collapse" id="topnav">
                <ul class="nav navbar-nav navbar-right">
                    <?php if ($showTools): ?>
                        <?php tpl_action('edit', 1, 'li'); ?>
                    <?php endif; ?>
                    <li class="dropdown">
                        <a href="#" class="dropdown-toggle" data-toggle="dropdown"><?php echo $lang['tools']; ?> <b class="caret"></b></a>
                        <ul class="dropdown-menu">
                            <li class="dropdown-header"><?php echo $lang['page_tools'] ?></li>
                            <?php
                                tpl_action('edit', 1, 'li');
                                if ($ACT == 'revisions') { tpl_action('revisions', 1, 'li class="active"'); } else { tpl_action('revisions', 1, 'li'); };
                                if ($ACT == 'backlink') { tpl_action('backlink', 1, 'li class="active"'); } else { tpl_action('backlink', 1, 'li'); };
                                tpl_action('subscribe', 1, 'li');
                                tpl_action('revert', 1, 'li');
                            ?>
                            <li class="dropdown-header"><?php echo $lang['site_tools'] ?></li>
                            <?php if ($showTools): ?>
                            <?php
                                if ($ACT == 'recent') { tpl_action('recent', 1, 'li class="active"'); } else { tpl_action('recent', 1, 'li'); };
                                if ($ACT == 'index') { tpl_action('index', 1, 'li class="active"'); } else { tpl_action('index', 1, 'li'); };
                                if ($ACT == 'media') { tpl_action('media', 1, 'li class="active"'); } else { tpl_action('media', 1, 'li'); };
                                if ($ACT == 'admin') { tpl_action('admin', 1, 'li class="active"'); } else { tpl_action('admin', 1, 'li'); };
                            ?>
                            <?php endif ?>
                            <?php if ($conf['useacl'] && $showTools): ?>
                            <li class="dropdown-header"><?php echo $lang['user_tools'] ?></li>
                            <?php
                                if ($ACT == 'profile') { tpl_action('profile', 1, 'li class="active"'); } else { tpl_action('profile', 1, 'li'); };
                                if ($ACT == 'login') { tpl_action('login', 1, 'li class="active"'); } else { tpl_action('login', 1, 'li'); };
                            ?>
                            <?php endif; ?>
                            <li class="divider"></li>
                            <?php /* the optional second parameter of tpl_action() switches between a link and a button,
                             e.g. a button inside a <li> would be: tpl_action('edit', 0, 'li') */
                                tpl_action('top', 1, 'li');
                            ?>
                        </ul>
                    </li>
                </ul>

                <?php _tpl_searchform() ?>
            </div>
        </div>

        <div class="container not-header">
            <div class="notifications">
                <?php html_msgarea() /* occasional error and info messages on top of the page */ ?>
            </div>

            <a href="#dokuwiki__content" class="sr-only "><?php echo $lang['skip_to_content']; ?></a>
            <a href="#dokuwiki__aside" class="skip-to-sidebar visible-xs btn-block btn btn-info"><?php echo "Skip to Navigation"; // echo $lang['skip_to_nav']; ?></a>

            <?php if($conf['breadcrumbs']) _tpl_breadcrumbs(); ?>

            <?php $sidebar_contents = bootstrap_tpl_get_sidebar($conf['sidebar'], false); ?>

            <section class="wrapper row"><!-- PAGE ACTIONS -->
                <!-- ********** CONTENT ********** -->
                <div id="dokuwiki__content" class="<?php
                    if ($ACT == 'show' && $sidebar_contents != ""):
                        ?>col-sm-<?php echo 12 - $sidebarCols; ?><?php
                        if ($sidebarPos == "Left"):
                            ?> col-sm-push-<?php echo $sidebarCols; ?> <?php
                        endif; ?><?php
                    else: ?>col-xs-12<?php
                    endif; ?>">
                    <?php if($conf['youarehere']){ ?>
                        <div class="youarehere">
                            <?php bootstrap_tpl_youarehere() ?>
                        </div>
                    <?php } ?>

                    <?php tpl_flush() /* flush the output buffer */ ?>
                    <?php tpl_includeFile('pageheader.html') ?>

                    <?php _tpl_toc(); ?>
                    <div class="page" role="main">
                    <!-- wikipage start -->
                        <?php
                        if ($ID == "starterbootstrap:index" && auth_quickaclcheck($id) > AUTH_CREATE) {
                            include_once("generate_index.php");
                        } else {
                            tpl_content(false); /* the main content */
                        }
                        ?>
                    <!-- wikipage stop -->
                    </div>

                    <?php tpl_includeFile('pagefooter.html') ?>
                </div><!-- /content -->

                <!-- ********** ASIDE ********** -->
                <?php if ($ACT == 'show'): ?>
                <aside id="dokuwiki__aside" class="col-sm-<?php echo $sidebarCols; ?><?php
                    if ($sidebarPos == "Left"):
                        ?> col-sm-pull-<?php echo 12 - $sidebarCols; ?><?php
                    endif; ?>">
                    <?php if ($showSidebar && $sidebarCols > 0): ?>
                    <div class="sidebar-page">
                        <?php
                            tpl_includeFile('sidebarheader.html');
                            echo $sidebar_contents;
                            tpl_includeFile('sidebarfooter.html');
                        ?>
                    </div>
                    <?php endif; ?>
                </aside><!-- /aside -->
                <?php endif; ?>
            </section><!-- /wrapper -->

            <!-- ********** FOOTER ********** -->
            <footer id="dokuwiki__footer">
                <ul class="doc breadcrumb pull-right">
                    <li><?php tpl_action('top', 1, ''); ?></li>
                    <li><?php tpl_pageinfo() /* 'Last modified' etc */ ?></li>
                </ul>
                <?php tpl_license('button') /* content license, parameters: img=*badge|button|0, imgonly=*0|1, return=*0|1 */ ?>
            </footer><!-- /footer -->

            <?php tpl_includeFile('footer.html') ?>
        </div>

    </div></div><!-- /site -->

    <div class="no"><?php tpl_indexerWebBug() /* provide DokuWiki housekeeping, required in all templates */ ?></div>
    <!--[if ( IE 6 | IE 7 | IE 8 ) ]></div><![endif]-->

    <?php @require_once(dirname(__FILE__).'/tail-js.php'); ?>
</body>
</html>
