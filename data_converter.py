import json
import xml.etree.ElementTree as ET
from xml.dom import minidom

class DataConverter:

    def json_to_xml(self, json_data):
        """Convert JSON data to XML format with pretty printing."""
        try:
            if isinstance(json_data, bytes):
                json_data = json_data.decode('utf-8')

            data = json.loads(json_data)
            root = ET.Element("root")

            # Check for 'users' in the JSON data and handle each user
            if 'users' in data:
                for user_data in data['users']:
                    # Create a 'users' tag for each user
                    user_element = ET.SubElement(root, 'users')
                    for key, value in user_data.items():
                        # Create child elements for each key-value pair in the user
                        child = ET.SubElement(user_element, key)
                        child.text = str(value)

            # Convert to a string and pretty print XML
            xml_str = ET.tostring(root, encoding="unicode")
            dom = minidom.parseString(xml_str)
            pretty_xml_str = dom.toprettyxml(indent="  ")

            return pretty_xml_str

        except Exception as e:
            raise Exception(f"Error in converting JSON to XML: {str(e)}")

    def xml_to_json(self, xml_data):
        """Convert XML data to JSON format."""
        try:
            root = ET.fromstring(xml_data)
            
            # Create a dictionary to hold the structured data
            data = {}

            # Process the children of the root element
            def parse_element(element):
                parsed_data = {}
                
                for child in element:
                    # If the child has sub-elements, recurse into them
                    if len(child):
                        parsed_data[child.tag] = parse_element(child)
                    else:
                        parsed_data[child.tag] = child.text
                
                return parsed_data

            # Initialize the root in the dictionary
            data['root'] = {}
            
            # Loop through the "users" elements
            users = []
            for user in root.findall('users'):
                user_data = parse_element(user)
                users.append(user_data)
            
            # Add users to the root data
            data['root']['users'] = users
            
            # Convert the dictionary to JSON format and return
            return json.dumps(data, indent=3)

        except Exception as e:
            raise Exception(f"Error in converting XML to JSON: {str(e)}")

    def xml_to_xsd(self, xml_data):
        try:
            root = ET.fromstring(xml_data)
            xsd_schema = """<?xml version="1.0" encoding="utf-8"?>
    <!-- Created with Liquid Technologies Online Tools 1.0 (https://www.liquid-technologies.com) -->
    <xs:schema attributeFormDefault="unqualified" elementFormDefault="qualified" xmlns:xs="http://www.w3.org/2001/XMLSchema">
    """
            xsd_schema += self.generate_xsd_element(root)
            xsd_schema += "</xs:schema>"
            return xsd_schema

        except Exception as e:
            raise Exception(f"Error in converting XML to XSD: {str(e)}")

    def generate_xsd_element(self, element, is_root=True):
        xsd = ""

        if len(element):
            if is_root and element.tag == "users":
                xsd += f"  <xs:element name='{element.tag}'>\n"
                xsd += "    <xs:complexType>\n"
                xsd += "      <xs:sequence>\n"
                xsd += f"        <xs:element name='user' maxOccurs='unbounded'>\n"
                xsd += "          <xs:complexType>\n"
                xsd += "            <xs:sequence>\n"
                for child in element:
                    if child.tag == "user":
                        for grandchild in child:
                            xsd += self.generate_xsd_element(grandchild, is_root=False)
                xsd += "            </xs:sequence>\n"
                xsd += "          </xs:complexType>\n"
                xsd += "        </xs:element>\n"
                xsd += "      </xs:sequence>\n"
                xsd += "    </xs:complexType>\n"
                xsd += "  </xs:element>\n"
            else:
                xsd += f"  <xs:element name='{element.tag}'>\n"
                xsd += "    <xs:complexType>\n"
                xsd += "      <xs:sequence>\n"
                for child in element:
                    xsd += self.generate_xsd_element(child, is_root=False)
                xsd += "      </xs:sequence>\n"
                xsd += "    </xs:complexType>\n"
                xsd += "  </xs:element>\n"
        else:
            if element.tag in ['id', 'age']:
                xsd += f"  <xs:element name='{element.tag}' type='xs:unsignedByte' />\n"
            else:
                xsd += f"  <xs:element name='{element.tag}' type='xs:string' />\n"

        return xsd

    def xsd_to_xml(self, xsd_data):
        try:
            root = ET.fromstring(xsd_data)

            def build_xml_from_xsd(element):
                xml_str = f"<{element.tag}>"
                for child in element:
                    xml_str += build_xml_from_xsd(child)
                xml_str += f"</{element.tag}>"
                return xml_str

            xml_data = build_xml_from_xsd(root)
            return xml_data

        except Exception as e:
            raise Exception(f"Error in converting XSD to XML: {str(e)}")

    def pretty_json(self, json_data):
        try:
            data = json.loads(json_data)
            return json.dumps(data, indent=4)
        except Exception as e:
            raise Exception(f"Error in formatting JSON: {str(e)}")

    def pretty_xml(self, xml_data):
        try:
            root = ET.fromstring(xml_data)
            xml_str = ET.tostring(root, encoding="unicode")
            dom = minidom.parseString(xml_str)
            pretty_xml_str = dom.toprettyxml(indent="  ")
            return pretty_xml_str
        except Exception as e:
            raise Exception(f"Error in formatting XML: {str(e)}")
