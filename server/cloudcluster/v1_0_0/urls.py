from django.urls import path, re_path
from django.conf.urls.static import static
from cloudcluster import settings
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

from . import views

schema_view = get_schema_view(
   openapi.Info(
      title="API",
      default_version='v1',
      description="API",
   ),
   public=True,
   permission_classes=[permissions.AllowAny]
)

urlpatterns = [
   re_path(r'^spec/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),

   path('is-alive', views.is_alive),
   path('get-version', views.get_version),
   path('is-registered', views.is_registered),
   path('select-tenant', views.select_tenant),
   path('active-tenants', views.get_active_tenants),
   path('user', views.user),
   path('profile', views.profile),
   path('profile/picture', views.user_profile_picture),
   path('task-message/<str:task_id>', views.get_task_message),

   path('tenants/<str:tenant_id>', views.account_tenant),
   path('tenants/<str:tenant_id>/settings', views.account_get_settings),

   path('tenants/<str:tenant_id>/users/<str:username>', views.get_specific_user_info),
   path('tenants/<str:tenant_id>/user-quotas', views.get_usage),
   path('tenants/<str:tenant_id>/unregistered-users', views.get_unregistered_users),

   path('tenants/<str:tenant_id>/projects', views.project_list),
   path('tenants/<str:tenant_id>/projects/<str:project_id>', views.project_detail),
   path('tenants/<str:tenant_id>/projects/<str:project_id>/users', views.project_users),
   path('tenants/<str:tenant_id>/projects/<str:project_id>/users/<str:username>', views.project_users_detail),
   path('tenants/<str:tenant_id>/projects/name-available/<str:name>', views.is_project_name_free),

   path('tenants/<str:tenant_id>/cloud-credentials', views.cloud_account_list),
   path('tenants/<str:tenant_id>/cloud-credentials/<str:cloudaccount_id>', views.cloud_account_detail),
   path('tenants/<str:tenant_id>/cloud-credentials/validate', views.validate_credentials),
   path('tenants/<str:tenant_id>/cloud-credentials/<str:cloudaccount_id>/validate', views.validate_credentials),
   path('tenants/<str:tenant_id>/cloud-credentials/providers/<str:provider>', views.get_provider_accounts),
   path('cloud-credentials/providers/<str:provider>/account-params', views.suggest_account_params),
   path('tenants/<str:tenant_id>/cloud-credentials/<str:cloudaccount_id>/storage-accounts', views.get_storage_accounts),
   path('tenants/<str:tenant_id>/cloud-credentials/<str:cloudaccount_id>/regions', views.get_valid_regions),
   path('tenants/<str:tenant_id>/cloud-credentials/<str:cloudaccount_id>/regions/<str:region>/zones', views.get_valid_zones),
   path('tenants/<str:tenant_id>/cloud-credentials/<str:cloudaccount_id>/regions/<str:region>/zones/<str:zone>/instances', views.get_valid_instances),
   path('tenants/<str:tenant_id>/cloud-credentials/<str:cloudaccount_id>/regions/<str:region>/instances', views.get_valid_instances),
   path('tenants/<str:tenant_id>/cloud-credentials/<str:cloudaccount_id>/regions/<str:region>/environment-type/<str:environment_type>/operating-systems', views.get_valid_operating_systems),
   path('tenants/<str:tenant_id>/cloud-credentials/<str:cloudaccount_id>/regions/update-status', views.check_account_regions_update_status),
   path('tenants/<str:tenant_id>/cloud-credentials/check-provided-credentials', views.check_provided_credentials),

   path('tenants/<str:tenant_id>/buckets', views.bucket_list),
   path('tenants/<str:tenant_id>/buckets/<str:bucket_id>', views.bucket_detail),
   path('tenants/<str:tenant_id>/buckets/<str:bucket_id>/files/<path:path>', views.bucket_files),
   path('tenants/<str:tenant_id>/buckets/<str:bucket_id>/files/<path:path>/download', views.download_bucket_file),

   path('tenants/<str:tenant_id>/clusters/<str:cluster_id>/details', views.get_cluster_details),
   path('tenants/<str:tenant_id>/clusters/<str:cluster_id>/storage', views.get_cluster_storage),
   path('tenants/<str:tenant_id>/clusters/<str:cluster_id>/config', views.get_cluster_config),
   path('tenants/<str:tenant_id>/clusters/<str:cluster_id>/kubeconfig', views.get_cluster_kubeconfig),
   path('tenants/<str:tenant_id>/clusters/<str:cluster_id>/wireguard-config', views.get_wireguard_config),
   path('tenants/<str:tenant_id>/clusters/<str:cluster_id>/installation-status', views.get_installation_status),
   path('tenants/<str:tenant_id>/clusters/<str:cluster_id>/resize-status', views.get_resize_status),
   path('tenants/<str:tenant_id>/clusters/<str:cluster_id>/user/<str:username>/kubeconfig', views.get_user_kubeconfig),

   path('oauth/azure/createApp', views.oauth_azure_create_app),
   path('oauth/azure/getsubscriptions', views.oauth_azure_get_subscriptions),
   path('oauth/azure/getauthurladminconsent', views.oauth_azure_get_auth_url_admin_consent),
   path('oauth/azure/getauthurlauthorize', views.oauth_azure_get_auth_url_authorize),
   path('oauth/azure/getauthurlcreateapp', views.oauth_azure_get_auth_url_create_app),
   path('azureauthorize', views.oauth_azure_authorize),
   path('azureadminconsent', views.oauth_azure_adminconsent),
   path('azurecreateapp', views.oauth_azure_createapp),
   path('oauth/google/getauthurlprojects', views.oauth_google_get_auth_url_projects),
   path('oauth/google/createserviceaccount', views.oauth_google_create_service_account),
   path('oauth/google/getprojects', views.oauth_google_get_projects),
   path('googleoauth', views.oauth_google),

   # ------------------------------------------------------------------------------------

   path('canUpdateUserPassword', views.can_update_user_password),
   path('updateuserpassword', views.change_user_password),
   path('updateUser', views.update_user),
   path('registerTenantUser', views.register_tenant_user),
   path('addnewuser', views.add_newuser),
   path('getuserslist', views.get_userslist),
   path('delete_user', views.delete_user),

   path('environmenttemplates/save', views.save_environment_template),
   path('environmenttemplates/create', views.create_environment_template),
   path('environmenttemplates/list', views.list_environment_templates),
   path('environmenttemplates/delete', views.delete_environment_template),
   path('environmenttemplates/get/<str:environmentTemplateId>', views.get_environment_template),
   path('environmenttemplates/isnamefree', views.is_environment_template_name_free),

   path('getClusterList', views.get_cluster_list),
   path('getKubernetesAvailableUpgradeVersions', views.get_kubernetes_available_upgrade_versions),
   path('generateClusterServiceDefaultName', views.generate_cluster_service_default_name),
   path('isClusterNameFree', views.is_cluster_name_free),
   path('isComputeNameFree', views.is_compute_name_free),
   path('isDLCMv2NameFree', views.is_dlcmv2_name_free),
   path('getServiceOptions', views.get_service_options),
   path('getServiceList', views.get_service_list),
   path('getServiceValues', views.get_service_values),
   path('getServiceConnectionInfo', views.get_service_connection_info),
   path('getTerraformPlan', views.get_tf_plan),
   path('addService', views.add_service),
   path('deleteService', views.delete_service),
   path('addUserToCluster', views.add_user_to_cluster),
   path('isclusterusernamefree', views.is_cluster_username_free),
   path('isclusterusernamevalid', views.is_cluster_username_valid),
   path('deleteUserFromCluster', views.delete_user_from_cluster),
   path('addMachinesToVMs', views.add_machines_to_vms),
   path('addMachinesToDlcm', views.add_machines_to_dlcm),
   path('addMachinesToDlcmV2', views.add_machines_to_dlcm_v2),
   path('checkforipconflicts', views.check_for_ip_conflicts),
   path('checkipaddress', views.check_ip_address),
   path('renameCluster', views.rename_cluster),
   path('deleteCluster', views.delete_cluster),
   path('removeComputeNode', views.remove_compute_node),
   path('stopCluster', views.stop_cluster),
   path('startCluster', views.start_cluster),
   path('restartCluster', views.restart_cluster),
   path('stopMachine', views.stop_machine),
   path('startMachine', views.start_machine),
   path('restartMachine', views.restart_machine),
   path('getsupportedkubernetesconfigurations', views.get_supported_kubernetes_configurations),
   path('getsupporteddlcmv2configurations', views.get_supported_kubeadm_configurations),
   path('getSupportedCapiKubernetesConfigurations', views.get_supported_capi_kubernetes_configurations),
   path('getSupportedYaookCapiKubernetesConfigurations', views.get_supported_yaookcapi_kubernetes_configurations),
   path('createDlcm', views.create_dlcm),
   path('retryCreateDlcm', views.retry_create_dlcm),
   path('retryResizeDlcm', views.retry_resize_dlcm),
   path('createDlcmV2', views.create_dlcm_v2),
   path('resizedlcmv2', views.resize_dlcm_v2),
   path('retryResizeDlcmV2', views.retry_resize_dlcm_v2),
   path('retryResizeVMsCluster', views.retry_resize_vms_cluster),
   path('upgradeKubernetesCluster', views.upgrade_kubernetes_cluster),
   path('createVMs', views.create_VMs),
   path('retryCreateVMs', views.retry_create_vms),
   path('createComputeVMs', views.create_compute_VMs),
   path('retryCreateComputeVMs', views.retry_create_compute_vms),
   path('cancelClusterCreation', views.cancel_cluster_creation),
   path('updateCluster/<str:cluster_id>', views.update_cluster),
   path('createCapiCluster', views.create_capi_cluster),
   path('resizeCapiCluster', views.resize_capi_cluster),
   path('retryCreateCapiCluster', views.retry_create_capi_cluster),
   path('deleteCapiCluster', views.delete_capi_cluster),
   path('createYaookCluster', views.create_yaookcapi_cluster),
   path('resizeYaookCluster', views.resize_yaookcapi_cluster),
   path('retryCreateYaookCluster', views.retry_create_yaookcapi_cluster),
   path('deleteYaookCluster', views.delete_yaookcapi_cluster),
   path('createK3sCluster', views.create_k3s_cluster),
   path('getsupportedk3sconfigurations', views.get_supported_k3s_configurations),
   path('retryCreateK3sCluster', views.retry_create_k3s_cluster),
   path('getK3sAvailableUpgradeVersions', views.get_k3s_available_upgrade_versions),
   path('upgradeK3sCluster', views.upgrade_k3s_cluster),
   path('addMachinesToK3s', views.add_machines_to_k3s),

] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)