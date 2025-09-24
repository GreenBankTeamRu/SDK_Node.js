import gost from './index';
import ab2str from 'arraybuffer-to-string';
import str2ab from 'string-to-arraybuffer';

const skrebok = str => gost.subtle.digest('GOST R 34.11', str2ab(str));

export { ab2str, str2ab, skrebok, skrebok as default };