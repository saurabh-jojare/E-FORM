//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace EFORM.Models
{
    using System;
    using System.Collections.Generic;
    
    public partial class IMS_SANCTIONED_PROJECTS
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public IMS_SANCTIONED_PROJECTS()
        {
            this.EFORM_MASTER = new HashSet<EFORM_MASTER>();
            this.EFORM_PIU_GENERAL_INFO = new HashSet<EFORM_PIU_GENERAL_INFO>();
            this.EFORM_PIU_MIX_DESIGN_DETAILS = new HashSet<EFORM_PIU_MIX_DESIGN_DETAILS>();
            this.EFORM_PIU_PREVIOUS_INSP_DETAILS = new HashSet<EFORM_PIU_PREVIOUS_INSP_DETAILS>();
            this.EFORM_PIU_PRGS_DETAILS = new HashSet<EFORM_PIU_PRGS_DETAILS>();
            this.EFORM_PIU_QC__DETAILS = new HashSet<EFORM_PIU_QC__DETAILS>();
            this.EFORM_QM_ARRANGEMENTS_OBS_DETAILS = new HashSet<EFORM_QM_ARRANGEMENTS_OBS_DETAILS>();
            this.EFORM_QM_GEOMETRICS_DETAILS = new HashSet<EFORM_QM_GEOMETRICS_DETAILS>();
            this.EFORM_QM_GEOMETRICS_OBS_DETAILS = new HashSet<EFORM_QM_GEOMETRICS_OBS_DETAILS>();
            this.EFORM_QM_PRESENT_WORK_DETAILS = new HashSet<EFORM_QM_PRESENT_WORK_DETAILS>();
            this.EFORM_QM_QC_TEST_DETAILS = new HashSet<EFORM_QM_QC_TEST_DETAILS>();
            this.EFORM_QM_QUALITY_ATTENTION = new HashSet<EFORM_QM_QUALITY_ATTENTION>();
            this.EFORM_QM_TEST_RESULT_VERIFICATION_DETAILS = new HashSet<EFORM_QM_TEST_RESULT_VERIFICATION_DETAILS>();
            this.EXEC_LSB_MONTHLY_STATUS = new HashSet<EXEC_LSB_MONTHLY_STATUS>();
            this.EXEC_ROADS_MONTHLY_STATUS = new HashSet<EXEC_ROADS_MONTHLY_STATUS>();
        }
    
        public int IMS_PR_ROAD_CODE { get; set; }
        public byte MAST_PMGSY_SCHEME { get; set; }
        public string IMS_PROPOSAL_TYPE { get; set; }
        public int IMS_YEAR { get; set; }
        public int IMS_BATCH { get; set; }
        public string IMS_PACKAGE_ID { get; set; }
        public int MAST_STATE_CODE { get; set; }
        public int MAST_DISTRICT_CODE { get; set; }
        public int MAST_BLOCK_CODE { get; set; }
        public int MAST_DPIU_CODE { get; set; }
        public Nullable<int> PLAN_CN_ROAD_CODE { get; set; }
        public string IMS_ROAD_NAME { get; set; }
        public string IMS_ROAD_FROM { get; set; }
        public string IMS_ROAD_TO { get; set; }
        public string IMS_UPGRADE_CONNECT { get; set; }
        public Nullable<int> MAST_EXISTING_SURFACE_CODE { get; set; }
        public Nullable<int> IMS_COLLABORATION { get; set; }
        public Nullable<int> IMS_STREAMS { get; set; }
        public string IMS_EXISTING_PACKAGE { get; set; }
        public string IMS_PARTIAL_LEN { get; set; }
        public decimal IMS_PAV_LENGTH { get; set; }
        public decimal IMS_PAV_EST_COST { get; set; }
        public int IMS_NO_OF_CDWORKS { get; set; }
        public decimal IMS_CD_WORKS_EST_COST { get; set; }
        public decimal IMS_PROTECTION_WORKS { get; set; }
        public decimal IMS_OTHER_WORK_COST { get; set; }
        public string IMS_IS_HIGHER_SPECIFICATION { get; set; }
        public Nullable<decimal> IMS_HIGHER_SPECIFICATION_COST { get; set; }
        public Nullable<decimal> IMS_FURNITURE_COST { get; set; }
        public Nullable<byte> IMS_SHARE_PERCENT { get; set; }
        public Nullable<byte> IMS_SHARE_PERCENT_2015 { get; set; }
        public decimal IMS_STATE_SHARE { get; set; }
        public Nullable<decimal> IMS_STATE_SHARE_2015 { get; set; }
        public Nullable<decimal> IMS_MORD_SHARE_2015 { get; set; }
        public Nullable<int> MAST_MP_CONST_CODE { get; set; }
        public Nullable<int> MAST_MLA_CONST_CODE { get; set; }
        public string IMS_ZP_RESO_OBTAINED { get; set; }
        public string IMS_PROPOSED_SURFACE { get; set; }
        public Nullable<int> IMS_CARRIAGED_WIDTH { get; set; }
        public Nullable<int> IMS_TRAFFIC_TYPE { get; set; }
        public string IMS_IS_STAGED { get; set; }
        public string IMS_STAGE_PHASE { get; set; }
        public Nullable<int> IMS_STAGED_YEAR { get; set; }
        public string IMS_STAGED_PACKAGE_ID { get; set; }
        public Nullable<int> IMS_STAGED_ROAD_ID { get; set; }
        public Nullable<int> IMS_NO_OF_BRIDGEWRKS { get; set; }
        public string IMS_BRIDGE_NAME { get; set; }
        public Nullable<decimal> IMS_BRIDGE_LENGTH { get; set; }
        public Nullable<decimal> IMS_BRIDGE_WORKS_EST_COST { get; set; }
        public Nullable<decimal> IMS_BRIDGE_EST_COST_STATE { get; set; }
        public string IMS_ISBENEFITTED_HABS { get; set; }
        public Nullable<int> IMS_HABS_REASON { get; set; }
        public decimal IMS_MAINTENANCE_YEAR1 { get; set; }
        public decimal IMS_MAINTENANCE_YEAR2 { get; set; }
        public decimal IMS_MAINTENANCE_YEAR3 { get; set; }
        public decimal IMS_MAINTENANCE_YEAR4 { get; set; }
        public decimal IMS_MAINTENANCE_YEAR5 { get; set; }
        public Nullable<decimal> IMS_RENEWAL_COST { get; set; }
        public string IMS_DPR_STATUS { get; set; }
        public string IMS_REMARKS { get; set; }
        public Nullable<decimal> IMS_CC_LENGTH { get; set; }
        public Nullable<decimal> IMS_BT_LENGTH { get; set; }
        public string STA_SANCTIONED { get; set; }
        public string STA_SANCTIONED_BY { get; set; }
        public Nullable<System.DateTime> STA_SANCTIONED_DATE { get; set; }
        public string IMS_STA_REMARKS { get; set; }
        public string PTA_SANCTIONED { get; set; }
        public Nullable<int> PTA_SANCTIONED_BY { get; set; }
        public Nullable<System.DateTime> PTA_SANCTIONED_DATE { get; set; }
        public string IMS_PTA_REMARKS { get; set; }
        public string IMS_SANCTIONED { get; set; }
        public Nullable<int> IMS_REASON { get; set; }
        public string IMS_SANCTIONED_BY { get; set; }
        public Nullable<System.DateTime> IMS_SANCTIONED_DATE { get; set; }
        public decimal IMS_SANCTIONED_PAV_AMT { get; set; }
        public decimal IMS_SANCTIONED_CD_AMT { get; set; }
        public decimal IMS_SANCTIONED_PW_AMT { get; set; }
        public decimal IMS_SANCTIONED_OW_AMT { get; set; }
        public Nullable<decimal> IMS_SANCTIONED_HS_AMT { get; set; }
        public Nullable<decimal> IMS_SANCTIONED_FC_AMT { get; set; }
        public decimal IMS_SANCTIONED_BW_AMT { get; set; }
        public decimal IMS_SANCTIONED_RS_AMT { get; set; }
        public decimal IMS_SANCTIONED_BS_AMT { get; set; }
        public decimal IMS_SANCTIONED_MAN_AMT1 { get; set; }
        public decimal IMS_SANCTIONED_MAN_AMT2 { get; set; }
        public decimal IMS_SANCTIONED_MAN_AMT3 { get; set; }
        public decimal IMS_SANCTIONED_MAN_AMT4 { get; set; }
        public decimal IMS_SANCTIONED_MAN_AMT5 { get; set; }
        public Nullable<decimal> IMS_SANCTIONED_RENEWAL_AMT { get; set; }
        public string IMS_PROG_REMARKS { get; set; }
        public Nullable<int> IMS_OLD_BLOCK_CODE { get; set; }
        public string IMS_OLD_PACKAGE_ID { get; set; }
        public Nullable<int> IMS_OLD_ROAD_ID { get; set; }
        public Nullable<decimal> IMS_VALUEOFWORK_DONE { get; set; }
        public Nullable<decimal> IMS_PAYMENT_MADE { get; set; }
        public string IMS_FINAL_PAYMENT_FLAG { get; set; }
        public Nullable<System.DateTime> IMS_FINAL_PAYMENT_DATE { get; set; }
        public Nullable<System.DateTime> IMS_ENTRY_DATE_FINANCIAL { get; set; }
        public Nullable<System.DateTime> IMS_ENTRY_DATE_PHYSICAL { get; set; }
        public string IMS_EXEC_REMARKS { get; set; }
        public string IMS_ISCOMPLETED { get; set; }
        public string IMS_LOCK_STATUS { get; set; }
        public string IMS_FREEZE_STATUS { get; set; }
        public string IMS_SHIFT_STATUS { get; set; }
        public Nullable<int> USERID { get; set; }
        public string IPADD { get; set; }
        public Nullable<decimal> IMS_RIDING_QUALITY_LENGTH { get; set; }
        public Nullable<decimal> IMS_PUCCA_SIDE_DRAINS { get; set; }
        public Nullable<decimal> IMS_GST_COST { get; set; }
        public string IMS_PROGRESS_STATUS_FREEZE { get; set; }
        public Nullable<System.DateTime> IMS_PROGRESS_STATUS_DATE { get; set; }
        public Nullable<decimal> IMS_MAINTENANCE_YEAR6 { get; set; }
        public Nullable<decimal> IMS_MAINTENANCE_YEAR7 { get; set; }
        public Nullable<decimal> IMS_MAINTENANCE_YEAR8 { get; set; }
        public Nullable<decimal> IMS_MAINTENANCE_YEAR9 { get; set; }
        public Nullable<decimal> IMS_MAINTENANCE_YEAR10 { get; set; }
        public Nullable<decimal> PUCCA_SIDE_DRAIN_LENGTH { get; set; }
        public Nullable<decimal> PROTECTION_LENGTH { get; set; }
        public Nullable<decimal> SURFACE_BRICK_SOLLING { get; set; }
        public Nullable<decimal> SURFACE_BT { get; set; }
        public Nullable<decimal> SURFACE_CC { get; set; }
        public Nullable<decimal> SURFACE_GRAVEL { get; set; }
        public Nullable<decimal> SURFACE_MOORUM { get; set; }
        public Nullable<decimal> SURFACE_TRACK { get; set; }
        public Nullable<decimal> SURFACE_WBM { get; set; }
        public Nullable<decimal> EXISTING_CARRIAGEWAY_WIDTH { get; set; }
        public Nullable<decimal> EXISTING_CARRIAGEWAY_PUC { get; set; }
    
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_MASTER> EFORM_MASTER { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_PIU_GENERAL_INFO> EFORM_PIU_GENERAL_INFO { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_PIU_MIX_DESIGN_DETAILS> EFORM_PIU_MIX_DESIGN_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_PIU_PREVIOUS_INSP_DETAILS> EFORM_PIU_PREVIOUS_INSP_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_PIU_PRGS_DETAILS> EFORM_PIU_PRGS_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_PIU_QC__DETAILS> EFORM_PIU_QC__DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_QM_ARRANGEMENTS_OBS_DETAILS> EFORM_QM_ARRANGEMENTS_OBS_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_QM_GEOMETRICS_DETAILS> EFORM_QM_GEOMETRICS_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_QM_GEOMETRICS_OBS_DETAILS> EFORM_QM_GEOMETRICS_OBS_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_QM_PRESENT_WORK_DETAILS> EFORM_QM_PRESENT_WORK_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_QM_QC_TEST_DETAILS> EFORM_QM_QC_TEST_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_QM_QUALITY_ATTENTION> EFORM_QM_QUALITY_ATTENTION { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_QM_TEST_RESULT_VERIFICATION_DETAILS> EFORM_QM_TEST_RESULT_VERIFICATION_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EXEC_LSB_MONTHLY_STATUS> EXEC_LSB_MONTHLY_STATUS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EXEC_ROADS_MONTHLY_STATUS> EXEC_ROADS_MONTHLY_STATUS { get; set; }
    }
}
