import importlib.util, io, os, tempfile, unittest
from pathlib import Path

class EquipmentTagsTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();os.environ['PANEL_DB']=str(Path(self.tmp.name)/'panel.db')
        path=os.environ.get('PANEL_APP_UNDER_TEST',str(Path(__file__).resolve().parents[1] / "panel-app/app.py"))
        spec=importlib.util.spec_from_file_location('panel_tags_'+self._testMethodName,path);self.mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.mod)
        self.client=self.mod.app.test_client()
        with self.mod.app.app_context():
            db=self.mod.db()
            db.execute("insert into vpns(id,plant,slug,host,port,username,password_enc,active,created_at,vpn_type) values(?,?,?,?,?,?,?,?,?,?)",(1,'Example Site Alpha','example-site-alpha','vpn.example.test','443','synthetic-user','',1,'now','ssl'))
            db.execute("insert into equipment(id,plant,name,kind,real_ip,real_port,active,created_at) values(?,?,?,?,?,?,?,?)",(1,'Example Site Alpha','Synthetic Equipment','WEB','192.0.2.10','80',1,'now'))
            db.execute("insert into equipment(id,plant,name,kind,real_ip,real_port,active,created_at) values(?,?,?,?,?,?,?,?)",(2,'Example Site Alpha','Synthetic Equipment Two','WEB','192.0.2.11','80',1,'now'))
            db.commit()
    def tearDown(self): self.tmp.cleanup()
    def login_admin(self):
        with self.client.session_transaction() as sess:sess['uid']=1
    def test_schema_seeds_the_fixed_tag_catalog(self):
        with self.mod.app.app_context():
            db=self.mod.db();tags=[row['name'] for row in db.execute('SELECT name FROM tags ORDER BY sort_order,id')];relation=[row['name'] for row in db.execute('PRAGMA table_info(equipment_tags)')]
        self.assertEqual(['Scada','Trackers','Inversores','CCTV','SET'],tags)
        self.assertEqual(['equipment_id','tag_id'],relation)


    def test_tags_are_normalized_validated_and_persisted(self):
        self.assertEqual(['Scada','CCTV'],self.mod.normalize_equipment_tags(['cctv','Scada','CCTV']))
        with self.assertRaisesRegex(ValueError,'Tag no válido'): self.mod.normalize_equipment_tags(['Solar'])
        with self.mod.app.app_context():
            db=self.mod.db();self.mod.set_equipment_tags(db,1,['CCTV','Scada']);db.commit()
            self.assertEqual(['Scada','CCTV'],self.mod.equipment_tag_names(db,1))
            self.mod.set_equipment_tags(db,1,['SET']);db.commit()
            self.assertEqual(['SET'],self.mod.equipment_tag_names(db,1))


    def test_admin_form_lists_all_tags_and_new_equipment_persists_multiple_tags(self):
        self.login_admin();body=self.client.get('/admin/equipment/new?plant=Example%20Site%20Alpha').get_data(as_text=True)
        for name in ['Scada','Trackers','Inversores','CCTV','SET']:
            self.assertIn("name='tags' value='"+name+"'",body)
        original=self.mod.publish_plant;self.mod.publish_plant=lambda plant:[]
        try:
            response=self.client.post('/admin/equipment/new?plant=Example%20Site%20Alpha',data={'plant':'Example Site Alpha','name':'Equipo etiquetado','kind':'RDP','real_ip':'198.51.100.40','real_port':'3389','public_port':'9000','tags':['Scada','SET'],'description':'Prueba'})
        finally: self.mod.publish_plant=original
        self.assertEqual(302,response.status_code)
        with self.mod.app.app_context():
            db=self.mod.db();eid=db.execute("SELECT id FROM equipment WHERE name='Equipo etiquetado'").fetchone()['id'];self.assertEqual(['Scada','SET'],self.mod.equipment_tag_names(db,eid))


    def test_edit_form_shows_selected_tags_and_replaces_them_on_save(self):
        self.login_admin()
        with self.mod.app.app_context():
            db=self.mod.db();self.mod.set_equipment_tags(db,1,['Scada','SET']);db.commit()
        body=self.client.get('/admin/equipment/1/edit').get_data(as_text=True)
        self.assertIn("value='Scada' checked",body);self.assertIn("value='SET' checked",body)
        original=self.mod.publish_plant;self.mod.publish_plant=lambda plant:[]
        try:
            response=self.client.post('/admin/equipment/1/edit',data={'plant':'Example Site Alpha','name':'SCADA','kind':'WEB','real_ip':'192.0.2.15','real_port':'80','path':'/signin','public_port':'8081','web_mode':'direct','tags':['Trackers','CCTV'],'description':'SCADA de planta'})
        finally: self.mod.publish_plant=original
        self.assertEqual(302,response.status_code)
        with self.mod.app.app_context(): self.assertEqual(['Trackers','CCTV'],self.mod.equipment_tag_names(self.mod.db(),1))


    def test_unknown_tag_is_rejected_without_creating_equipment(self):
        self.login_admin()
        response=self.client.post('/admin/equipment/new?plant=Example%20Site%20Alpha',data={'plant':'Example Site Alpha','name':'No válido','kind':'RDP','real_ip':'198.51.100.41','real_port':'3389','public_port':'9001','tags':['Solar']})
        self.assertEqual(400,response.status_code);self.assertIn('Tag no válido',response.get_data(as_text=True))
        with self.mod.app.app_context(): self.assertIsNone(self.mod.db().execute("SELECT id FROM equipment WHERE name='No válido'").fetchone())


    def test_csv_template_and_parser_support_pipe_separated_tags(self):
        self.login_admin();template=self.client.get('/admin/equipment/import/template.csv').get_data(as_text=True)
        self.assertIn(';tags',template.splitlines()[0])
        raw=('nombre;tipo;ip;puerto;ruta;puerto_publico;modo_web;url_publica;descripcion;usuario_rdp;password_rdp;dominio_rdp;remote_app;tags\n'
             'Equipo CSV;WEB;192.0.2.50;80;/;9100;direct;;Prueba;;;;;Scada|CCTV\n').encode()
        with self.mod.app.app_context(): parsed=self.mod.parse_bulk_csv(raw,'Example Site Alpha',set(),{})
        self.assertEqual(['Scada','CCTV'],parsed[0]['tags'])
        invalid=raw.replace(b'Scada|CCTV',b'Solar')
        with self.mod.app.app_context(),self.assertRaisesRegex(ValueError,'Fila 2: Tag no válido'): self.mod.parse_bulk_csv(invalid,'Example Site Alpha',set(),{})


    def test_bulk_import_persists_tags_for_the_equipment(self):
        self.login_admin();raw=('nombre;tipo;ip;puerto;ruta;puerto_publico;modo_web;url_publica;descripcion;usuario_rdp;password_rdp;dominio_rdp;remote_app;tags\n'
             'Importado tags;WEB;192.0.2.51;80;/;9101;direct;;Prueba;;;;;Trackers|SET\n').encode()
        original=self.mod.publish_plant;self.mod.publish_plant=lambda plant:[]
        try: response=self.client.post('/admin/equipment/plant/Example%20Site%20Alpha/import',data={'csv_file':(io.BytesIO(raw),'tags.csv')},content_type='multipart/form-data')
        finally: self.mod.publish_plant=original
        self.assertEqual(302,response.status_code)
        with self.mod.app.app_context():
            db=self.mod.db();eid=db.execute("SELECT id FROM equipment WHERE name='Importado tags'").fetchone()['id'];self.assertEqual(['Trackers','SET'],self.mod.equipment_tag_names(db,eid))


    def test_deleting_equipment_removes_its_tag_relations(self):
        self.login_admin()
        with self.mod.app.app_context():
            db=self.mod.db();self.mod.set_equipment_tags(db,1,['Scada']);db.commit()
        original=self.mod.publish_plant;self.mod.publish_plant=lambda plant:[]
        try: response=self.client.post('/admin/equipment/1/delete')
        finally: self.mod.publish_plant=original
        self.assertEqual(302,response.status_code)
        with self.mod.app.app_context(): self.assertEqual(0,self.mod.db().execute('SELECT COUNT(*) FROM equipment_tags WHERE equipment_id=1').fetchone()[0])


    def test_plant_table_displays_tags_and_exposes_tag_sorting(self):
        self.login_admin()
        with self.mod.app.app_context():
            db=self.mod.db();self.mod.set_equipment_tags(db,1,['Scada','SET']);db.commit()
        body=self.client.get('/plant/Example%20Site%20Alpha').get_data(as_text=True)
        self.assertIn("data-sort-key='tags'",body)
        self.assertIn("data-sort-value='scada|set'",body)
        self.assertIn("<span class='badge tag-badge tag-scada'>Scada</span>",body)
        self.assertIn("<span class='badge tag-badge tag-set'>SET</span>",body)
        self.assertIn("class='equipment-tags' data-sort-value=''",body)


    def test_admin_equipment_list_displays_tags(self):
        self.login_admin()
        with self.mod.app.app_context():
            db=self.mod.db();self.mod.set_equipment_tags(db,1,['Scada','CCTV']);db.commit()
        body=self.client.get('/admin/equipment/plant/Example%20Site%20Alpha').get_data(as_text=True)
        self.assertIn('<th>Tags</th>',body)
        self.assertIn("<span class='badge tag-badge tag-scada'>Scada</span>",body)
        self.assertIn("<span class='badge tag-badge tag-cctv'>CCTV</span>",body)


    def test_csv_duplicate_without_tags_preserves_existing_tags(self):
        with self.mod.app.app_context():
            db=self.mod.db();old=db.execute('SELECT * FROM equipment WHERE id=1').fetchone();self.mod.set_equipment_tags(db,1,['Scada','SET']);db.commit()
            raw=('nombre;tipo;ip;puerto;modo_web\nSCADA actualizada;WEB;192.0.2.10;80;direct\n').encode()
            parsed=self.mod.parse_bulk_csv(raw,'Example Site Alpha',set(),{self.mod.equipment_ip_key(old['real_ip']):old})
            self.assertEqual(['Scada','SET'],parsed[0]['tags'])


    def test_edit_validation_error_keeps_all_selected_tags_in_form(self):
        self.login_admin()
        with self.mod.app.app_context():
            db=self.mod.db();self.mod.set_equipment_tags(db,1,['Scada']);db.commit()
        response=self.client.post('/admin/equipment/1/edit',data={'plant':'Example Site Alpha','name':'SCADA','kind':'WEB','real_ip':'192.0.2.15','real_port':'no-valido','public_port':'8081','web_mode':'direct','tags':['CCTV','SET']})
        body=response.get_data(as_text=True);self.assertEqual(400,response.status_code)
        self.assertIn("value='CCTV' checked",body);self.assertIn("value='SET' checked",body)
        with self.mod.app.app_context(): self.assertEqual(['Scada'],self.mod.equipment_tag_names(self.mod.db(),1))


    def test_tag_badges_have_distinct_light_and_dark_color_tokens(self):
        self.login_admin()
        with self.mod.app.app_context():
            db=self.mod.db();self.mod.set_equipment_tags(db,1,list(self.mod.EQUIPMENT_TAG_CATALOG));db.commit()
        body=self.client.get('/plant/Example%20Site%20Alpha').get_data(as_text=True)
        expected={'Scada':'scada','Trackers':'trackers','Inversores':'inversores','CCTV':'cctv','SET':'set'}
        for label,slug in expected.items():
            self.assertIn(f"class='badge tag-badge tag-{slug}'>{label}</span>",body)
            self.assertIn(f'.tag-{slug}{{--tag-fg:',body)
            self.assertIn(f"[data-theme='dark'] .tag-{slug}",body)

    def test_equipment_lists_offer_multi_tag_filter_with_or_matching(self):
        self.login_admin()
        with self.mod.app.app_context():
            db=self.mod.db();self.mod.set_equipment_tags(db,1,['Scada','CCTV']);self.mod.set_equipment_tags(db,2,['SET']);db.commit()
        user_body=self.client.get('/plant/Example%20Site%20Alpha').get_data(as_text=True)
        admin_body=self.client.get('/admin/equipment/plant/Example%20Site%20Alpha').get_data(as_text=True)
        for body in (user_body,admin_body):
            self.assertIn("data-tag-filter",body)
            self.assertEqual(5,body.count("data-filter-tag="))
            self.assertIn("data-filter-tag='Scada'",body)
            self.assertIn("data-filter-tag='SET'",body)
            self.assertIn("data-filter-count",body)
        self.assertIn("data-tags='scada,cctv'",user_body)
        self.assertIn("data-tags='set'",user_body)
        self.assertIn('map(x=>x.dataset.filterTag.toLowerCase())',user_body)
        self.assertIn('selected.some(tag=>rowTags.includes(tag))',user_body)
        self.assertIn('row.hidden=!visible',user_body)
        self.assertIn('[hidden]{display:none!important}',user_body)

if __name__=='__main__': unittest.main()
