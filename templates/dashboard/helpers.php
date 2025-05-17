<?php
/**
 * Helper function to render permission badges
 * Place this in a helpers.php file and include it in your project
 */
function renderPermissionBadges($userPermissions, $showAll = true) {
    $allPermissions = ['upload', 'view', 'download', 'archive', 'delete'];
    $output = '';
    
    // Ensure userPermissions is an array
    if (!is_array($userPermissions)) {
        $userPermissions = [];
    }
    
    foreach ($allPermissions as $perm) {
        $hasPermission = in_array($perm, $userPermissions);
        
        // Skip rendering this permission if showAll is false and user doesn't have it
        if (!$showAll && !$hasPermission) {
            continue;
        }
        
        $badgeClass = $hasPermission 
            ? 'bg-green-100 text-green-800' 
            : 'bg-gray-100 text-gray-400';
            
        $output .= '<span class="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ' . $badgeClass . ' mr-1">' . 
                   ucfirst($perm) . 
                   '</span>';
    }
    
    return $output;
}